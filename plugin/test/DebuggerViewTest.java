import com.google.gson.*;
import java.net.*;
import java.nio.*;
import java.nio.file.*;
import java.lang.reflect.*;
import java.util.*;
import javax.swing.*;
import java.awt.*;
import java.awt.image.*;
import javax.imageio.ImageIO;

public class DebuggerViewTest {
  static Object field(Object o, String name) throws Exception {
    Field f = o.getClass().getDeclaredField(name);
    f.setAccessible(true);
    return f.get(o);
  }
  static void layout(Container c) {
    c.doLayout();
    for (Component child : c.getComponents())
      if (child instanceof Container cc)
        layout(cc);
  }
  public static void main(String[] args) throws Exception {
    System.setProperty("java.awt.headless", "true");
    try (URLClassLoader loader = new URLClassLoader(new URL[] {Path.of(args[0]).toUri().toURL()})) {
      Class<?> plugin = loader.loadClass("ebpfproxy.CommunicationOrigins");
      Method ip = plugin.getDeclaredMethod("displayIP", String.class);
      ip.setAccessible(true);
      if (!ip.invoke(null, "::ffff:c000:201").equals("192.0.2.1")
          || !ip.invoke(null, "0:0:0:0:0:ffff:192.0.2.1").equals("192.0.2.1")
          || !ip.invoke(null, "2001:db8::1").equals("2001:db8::1"))
        throw new AssertionError("IP formatting");
      Object view = loader.loadClass("ebpfproxy.DebuggerView").getConstructor().newInstance();
      Method show = view.getClass().getMethod("showSnapshot", JsonObject.class);
      JsonObject snap = new JsonObject(), regs = new JsonObject();
      snap.addProperty("connectionId", "test/run/1");
      snap.addProperty("capturedAtBootNs", "1");
      snap.addProperty("pid", 42);
      snap.addProperty("tid", 43);
      snap.addProperty("syscallPc", "0x0000000000401000");
      snap.addProperty("stackBase", "0x0000000000001000");
      snap.addProperty("status", "partial-read");
      snap.addProperty("operation", "send");
      regs.addProperty("rsp", "0x0000000000001000");
      regs.addProperty("rbp", "0x0000000000001010");
      regs.addProperty("rip", "0x0000000000401002");
      regs.addProperty("rflags", "0x0000000000000246");
      snap.add("registers", regs);
      byte[] raw = new byte[64];
      ByteBuffer b = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
      b.putLong(16, 0x1020);
      b.putLong(24, 0x401234);
      b.putLong(32, 0);
      b.putLong(40, 0x405678);
      snap.addProperty("stack", Base64.getEncoder().encodeToString(raw));
      SwingUtilities.invokeAndWait(() -> {
        try {
          show.invoke(view, snap);
          JTable frames = (JTable) field(view, "frames"), memory = (JTable) field(view, "memory");
          if (((JTable) field(view, "registers")).getColumnCount() != 2)
            throw new AssertionError("unexpected Meaning column");
          if (frames.getRowCount() != 3 || !frames.getValueAt(2, 1).equals("0x0000000000405678")
              || memory.getRowCount() != 8)
            throw new AssertionError("frame chain or word decoding");
          Method follow = view.getClass().getDeclaredMethod("selectAddress", long.class);
          follow.setAccessible(true);
          follow.invoke(view, 0x1020L);
          if (memory.getSelectedRow() != 4)
            throw new AssertionError("pointer navigation");
          JPanel panel = (JPanel) view;
          panel.setSize(1280, 650);
          layout(panel);
          BufferedImage image = new BufferedImage(1280, 650, BufferedImage.TYPE_INT_RGB);
          Graphics2D g = image.createGraphics();
          panel.paint(g);
          g.dispose();
          ImageIO.write(image, "png", Path.of(args[1]).toFile());
          b.putLong(32, 0x1010);
          snap.addProperty("stack", Base64.getEncoder().encodeToString(raw));
          show.invoke(view, snap);
          if (frames.getRowCount() != 3
              || !((JLabel) field(view, "unwindStatus")).getText().contains("Non-increasing"))
            throw new AssertionError("cycle handling");
          snap.addProperty("stack", Base64.getEncoder().encodeToString(Arrays.copyOf(raw, 25)));
          show.invoke(view, snap);
          if (frames.getRowCount() != 1)
            throw new AssertionError("read beyond snapshot");
          show.invoke(view, new Object[] {null});
          if (memory.getRowCount() != 0 || frames.getRowCount() != 0)
            throw new AssertionError("stale event");
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      });
      System.out.println("PASS: IPv4 normalization, bounded RBP chain, pointer navigation, "
                         + "cycle/truncation handling, selection clearing");
    }
  }
}
