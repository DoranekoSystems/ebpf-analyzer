package ebpfproxy;
import com.google.gson.*;
import java.lang.reflect.*;
import javax.swing.*;
public class TableRefreshTest {
  static Object field(Object o, String name) throws Exception {
    Field f = o.getClass().getDeclaredField(name);
    f.setAccessible(true);
    return f.get(o);
  }
  static void call(Object o, String name) throws Exception {
    Method m = o.getClass().getDeclaredMethod(name);
    m.setAccessible(true);
    m.invoke(o);
  }
  public static void main(String[] args) throws Exception {
    System.setProperty("java.awt.headless", "true");
    SwingUtilities.invokeAndWait(() -> {
      try {
        CommunicationOrigins p = new CommunicationOrigins();
        p.createPanel();
        JsonObject root =
            JsonParser
                .parseString(
                    "{\"running\":true,\"updatedAtEpochMs\":1000,\"connections\":[{"
                    + "\"connectionId\":\"boot/run/"
                    + "1000000\",\"pid\":12,\"uid\":1,\"validFromEpochMs\":1000,\"validToEpochMs\":"
                    + "2000}],\"packets\":[{\"connectionId\":\"boot/run/"
                    + "1000000\",\"atEpochMs\":1000,\"data\":\"\",\"originalLength\":0}],"
                    + "\"ioEvents\":[{\"connectionId\":\"boot/run/"
                    + "1000000\",\"eventId\":\"event1\",\"capturedAtBootNs\":\"1000000\","
                    + "\"operation\":\"send\",\"tid\":13}]}")
                .getAsJsonObject();
        Method render = p.getClass().getDeclaredMethod("render", JsonObject.class);
        render.setAccessible(true);
        render.invoke(p, root);
        JTable main = (JTable) field(p, "connections"), packets = (JTable) field(p, "packets"),
               io = (JTable) field(p, "ioEvents");
        Object before = main.getValueAt(0, 0);
        root.getAsJsonArray("connections")
            .get(0)
            .getAsJsonObject()
            .addProperty("validFromEpochMs", 1001);
        render.invoke(p, root);
        if (!before.equals(main.getValueAt(0, 0)))
          throw new AssertionError("SYN time changed");
        main.setRowSelectionInterval(0, 0);
        if (packets.getRowCount() != 1 || io.getRowCount() != 1)
          throw new AssertionError("Missing detail rows");
        ((JMenuItem) packets.getComponentPopupMenu().getComponent(0)).doClick();
        ((JMenuItem) io.getComponentPopupMenu().getComponent(0)).doClick();
        render.invoke(p, root);
        if (packets.getRowCount() != 0 || io.getRowCount() != 0)
          throw new AssertionError("Cleared rows reappeared");
        JsonObject next = root.getAsJsonArray("ioEvents").get(0).getAsJsonObject().deepCopy();
        next.addProperty("eventId", "event2");
        root.getAsJsonArray("ioEvents").add(next);
        JsonObject packet = root.getAsJsonArray("packets").get(0).getAsJsonObject().deepCopy();
        packet.addProperty("atEpochMs", 2000);
        root.getAsJsonArray("packets").add(packet);
        render.invoke(p, root);
        if (packets.getRowCount() != 1 || io.getRowCount() != 1)
          throw new AssertionError("New rows hidden");
        ((JMenuItem) main.getComponentPopupMenu().getComponent(0)).doClick();
        render.invoke(p, root);
        if (main.getRowCount() != 0)
          throw new AssertionError("Connections reappeared");
        JsonObject flow = root.getAsJsonArray("connections").get(0).getAsJsonObject().deepCopy();
        flow.addProperty("connectionId", "boot/run/2000000");
        root.getAsJsonArray("connections").add(flow);
        render.invoke(p, root);
        if (main.getRowCount() != 1)
          throw new AssertionError("New connection hidden");
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    });
    System.out.println("PASS: stable SYN time, Clear on all tables, refresh suppression, new "
                       + "observations visible");
  }
}
