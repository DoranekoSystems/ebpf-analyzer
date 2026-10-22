import com.google.gson.*;
import java.net.*;
import java.nio.file.*;
import java.lang.reflect.*;
import javax.swing.*;
import javax.swing.table.*;

/** Regression: losing a connection selection must never broaden to all packets. */
public class PacketSelectionTest {
  static Object plugin;
  static Class<?> type;
  static Object field(String name) throws Exception {
    Field f = type.getDeclaredField(name);
    f.setAccessible(true);
    return f.get(plugin);
  }
  static String viewText(String name) throws Exception {
    Object view = field("eventView");
    Field f = view.getClass().getDeclaredField(name);
    f.setAccessible(true);
    JTable table = (JTable) f.get(view);
    StringBuilder out = new StringBuilder();
    for (int r = 0; r < table.getRowCount(); r++)
      for (int c = 0; c < table.getColumnCount(); c++)
        out.append(table.getValueAt(r, c)).append(' ');
    return out.toString();
  }
  static void call(String name, Class<?>[] signature, Object... args) throws Exception {
    Method m = type.getDeclaredMethod(name, signature);
    m.setAccessible(true);
    m.invoke(plugin, args);
  }
  static JsonObject flow(String id, int pid, String ip, int port) {
    JsonObject c = new JsonObject();
    c.addProperty("connectionId", id);
    c.addProperty("pid", pid);
    c.addProperty("uid", 10000 + pid);
    c.addProperty("appName", "app" + pid);
    c.addProperty("clientIp", "10.0.2.15");
    c.addProperty("clientPort", port);
    c.addProperty("serverIp", ip);
    c.addProperty("serverPort", 443);
    c.addProperty("validFromEpochMs", 100);
    c.addProperty("validToEpochMs", 200);
    c.addProperty("closed", false);
    return c;
  }
  static JsonObject packet(String id, String from, String to) {
    JsonObject p = new JsonObject();
    p.addProperty("connectionId", id);
    p.addProperty("source", from);
    p.addProperty("destination", to);
    p.addProperty("protocol", "TCP");
    p.addProperty("data", "AQ==");
    p.addProperty("originalLength", 1);
    p.addProperty("atEpochMs", 150);
    return p;
  }
  static JsonObject fixture() {
    JsonObject root = new JsonObject();
    root.addProperty("schemaVersion", 1);
    root.addProperty("mode", "passive");
    root.addProperty("running", true);
    root.addProperty("updatedAtEpochMs", System.currentTimeMillis());
    JsonArray flows = new JsonArray();
    flows.add(flow("A", 10, "1.1.1.1", 40001));
    flows.add(flow("B", 20, "8.8.8.8", 40002));
    root.add("connections", flows);
    JsonArray packets = new JsonArray();
    packets.add(packet("A", "10.0.2.15:40001", "1.1.1.1:443"));
    packets.add(packet("A", "1.1.1.1:443", "10.0.2.15:40001"));
    packets.add(packet("B", "10.0.2.15:40002", "8.8.8.8:443"));
    packets.add(packet("", "9.9.9.9:443", "10.0.2.15:40003"));
    root.add("packets", packets);
    return root;
  }
  static JsonObject event(String id, int tid, String pc, String stack) {
    JsonObject e = new JsonObject();
    e.addProperty("connectionId", "A");
    e.addProperty("eventId", id);
    e.addProperty("capturedAtBootNs", Integer.toString(tid));
    e.addProperty("tid", tid);
    e.addProperty("pid", 10);
    e.addProperty("operation", "send");
    e.addProperty("phase", "entry");
    e.addProperty("syscallPc", pc);
    e.addProperty("stackBase", "0x0000000000001000");
    e.addProperty("stack", stack);
    e.addProperty("architecture", "x86_64");
    e.addProperty("requestedBytes", 16384);
    e.addProperty("capturedBytes", 1);
    e.add("registers", new JsonObject());
    return e;
  }
  static void count(int expected) throws Exception {
    int actual = ((JTable) field("packets")).getRowCount();
    if (actual != expected)
      throw new AssertionError("expected " + expected + " packets, got " + actual);
  }
  public static void main(String[] args) throws Exception {
    System.setProperty("java.awt.headless", "true");
    Path input = Files.createTempFile("packet-selection-", ".json");
    Files.writeString(input, fixture().toString());
    System.setProperty("packetproxy.monitor.file", input.toString());
    try (URLClassLoader loader = new URLClassLoader(new URL[] {Path.of(args[0]).toUri().toURL()})) {
      type = loader.loadClass("ebpfproxy.CommunicationOrigins");
      plugin = type.getConstructor().newInstance();
      SwingUtilities.invokeAndWait(() -> {
        try {
          type.getMethod("createPanel").invoke(plugin);
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      });
      boolean[] busy = {true};
      for (int i = 0; i < 50 && busy[0]; i++) {
        Thread.sleep(50);
        SwingUtilities.invokeAndWait(() -> {
          try {
            busy[0] = (boolean) field("busy");
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
        });
      }
      if (busy[0])
        throw new AssertionError("reader did not finish");
      SwingUtilities.invokeAndWait(() -> {
        try {
          JTable connections = (JTable) field("connections"), packets = (JTable) field("packets");
          count(0); // Previously displayed all 4 packets without any selection.
          connections.setRowSelectionInterval(0, 0);
          count(2);
          JsonObject withEvents = fixture();
          JsonArray ev = new JsonArray();
          ev.add(event("first", 101, "0x0000000000001234", "AQ=="));
          ev.add(event("second", 102, "0x0000000000005678", "Ag=="));
          withEvents.add("ioEvents", ev);
          call("render", new Class<?>[] {JsonObject.class}, withEvents);
          JTable events = (JTable) field("ioEvents");
          if (events.getRowCount() != 2)
            throw new AssertionError("events overwritten by connection");
          if (events.getColumnCount() != 6 || !events.getColumnName(0).equals("Time")
              || !events.getColumnName(4).equals("Length"))
            throw new AssertionError("I/O columns");
          if (connections.getColumnCount() != 7 || !connections.getColumnName(0).equals("SYN Time")
              || !connections.getColumnName(6).equals("Updated"))
            throw new AssertionError("connection times");
          events.setRowSelectionInterval(0, 0);
          if (!viewText("registers").contains("5678") || !viewText("memory").contains("02 "))
            throw new AssertionError("second event context missing");
          events.setRowSelectionInterval(1, 1);
          if (!viewText("registers").contains("1234") || !viewText("memory").contains("01 "))
            throw new AssertionError("first event context missing");
          events.getRowSorter().toggleSortOrder(2);
          call("render", new Class<?>[] {JsonObject.class}, withEvents);
          if (!"first".equals(field("selectedEvent")))
            throw new AssertionError("sorted event identity changed");
          call("render", new Class<?>[] {JsonObject.class}, fixture());
          if (field("selectedEvent") != null || viewText("registers").contains("1234"))
            throw new AssertionError("evicted event context remains");
          if (!packets.getValueAt(0, 5).equals("\u2192")
              || !packets.getValueAt(1, 5).equals("\u2190") || packets.getColumnCount() != 6)
            throw new AssertionError("directions/context incorrect");
          packets.setRowSelectionInterval(0, 0);
          JsonObject reordered = fixture();
          JsonArray reverse = new JsonArray();
          reverse.add(reordered.getAsJsonArray("connections").get(1));
          reverse.add(reordered.getAsJsonArray("connections").get(0));
          reordered.add("connections", reverse);
          call("render", new Class<?>[] {JsonObject.class}, reordered);
          count(2);
          if (!"A".equals(field("selected")))
            throw new AssertionError("refresh switched connection identity");
          if (!((JTextArea) field("bytes")).getText().contains("01"))
            throw new AssertionError("selected packet hex lost");
          connections.clearSelection();
          count(0);
          if (!((JTextArea) field("bytes")).getText().isEmpty())
            throw new AssertionError("stale packet hex remains");
          connections.setRowSelectionInterval(0, 0);
          count(1);
          @SuppressWarnings("unchecked")
          TableRowSorter<DefaultTableModel> sorter =
              (TableRowSorter<DefaultTableModel>) connections.getRowSorter();
          sorter.setRowFilter(RowFilter.regexFilter("no-match"));
          count(0);
          sorter.setRowFilter(null);
          connections.setRowSelectionInterval(1, 1);
          count(2);
          JsonObject removed = fixture();
          removed.getAsJsonArray("connections").remove(0);
          call("render", new Class<?>[] {JsonObject.class}, removed);
          count(0);
          call("clear", new Class<?>[] {});
          count(0);
          JsonObject timed = fixture();
          timed.getAsJsonArray("connections")
              .get(0)
              .getAsJsonObject()
              .addProperty("connectionId", "boot/1000500000");
          call("render", new Class<?>[] {JsonObject.class}, timed);
          JsonObject timedEvent = event("clock", 101, "0x000000000000abcd", "AQ==");
          timedEvent.addProperty("connectionId", "boot/1000500000");
          timedEvent.addProperty("capturedAtBootNs", "1001750000");
          Method clock = type.getDeclaredMethod("eventTime", JsonObject.class);
          clock.setAccessible(true);
          String expectedTime = java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
                                    .format(java.time.Instant.ofEpochMilli(101).atZone(
                                        java.time.ZoneId.systemDefault()));
          if (!clock.invoke(plugin, timedEvent).equals(expectedTime))
            throw new AssertionError("I/O clock conversion");
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      });
      System.out.println("PASS: no implicit all-packets view, TX/RX, refresh by connection ID, "
                         + "clear/filter/eviction stay empty, stale hex cleared");
    } finally {
      Files.deleteIfExists(input);
    }
  }
}
