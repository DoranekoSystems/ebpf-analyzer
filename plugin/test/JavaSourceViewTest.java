package ebpfproxy;

import com.google.gson.*;
import java.awt.Color;
import java.nio.file.*;
import javax.swing.*;
import javax.swing.text.*;

public class JavaSourceViewTest {
  static java.awt.image.BufferedImage render(JComponent component) {
    component.setSize(1000, 100);
    component.doLayout();
    java.awt.image.BufferedImage image = new java.awt.image.BufferedImage(1000, 100, java.awt.image.BufferedImage.TYPE_INT_RGB);
    java.awt.Graphics2D g = image.createGraphics();
    component.paint(g);
    g.dispose();
    return image;
  }
  static void checkHighlightedText() throws Exception {
    JavaSourceView.SourcePane pane = new JavaSourceView.SourcePane();
    pane.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 18));
    JavaSourceView.highlight(pane, "public void onCreate() { String text = \"visible\"; return; }\n");
    java.awt.image.BufferedImage before = render(pane);
    JavaSourceView.markMethod(pane, 0);
    java.awt.image.BufferedImage after = render(pane);
    int dark = 0, retained = 0;
    for (int y = 0; y < 40; y++) for (int x = 0; x < 950; x++) {
      Color original = new Color(before.getRGB(x, y));
      if (original.getRed() < 180 && original.getGreen() < 180 && original.getBlue() < 190) {
        dark++;
        Color highlighted = new Color(after.getRGB(x, y));
        if (highlighted.getRed() < 180 && highlighted.getGreen() < 180 && highlighted.getBlue() < 190) retained++;
      }
    }
    if (dark < 100 || retained < dark * .95) throw new AssertionError("background erased syntax-colored glyphs: " + retained + "/" + dark);
    if (after.getRGB(940, 10) != new Color(255, 240, 185).getRGB()) throw new AssertionError("full row background missing");
    javax.imageio.ImageIO.write(after, "png", Path.of("plugin/build/tests/source-highlight.png").toFile());
  }
  public static void main(String[] args) throws Exception {
    JsonObject snapshot = JsonParser.parseString("{\"schemaVersion\":1,\"mode\":\"passive\",\"connections\":[],\"packets\":[],\"origins\":[{\"connectionId\":\"a\",\"architecture\":\"x86_64\",\"stackBase\":\"0x0000000000001000\",\"registers\":{}}]}").getAsJsonObject();
    JsonObject saved = snapshot.getAsJsonArray("origins").get(0).getAsJsonObject();
    Path capture = Files.createTempFile("stack-compatibility-", ".json");
    try {
      for (int size : new int[] {4096, 16384}) {
        saved.addProperty("requestedBytes", size);
        saved.addProperty("capturedBytes", size);
        saved.addProperty("stack", java.util.Base64.getEncoder().encodeToString(new byte[size]));
        Files.writeString(capture, snapshot.toString());
        CommunicationOrigins.read(capture);
      }
      saved.addProperty("requestedBytes", 4096);
      Files.writeString(capture, snapshot.toString());
      try {
        CommunicationOrigins.read(capture);
        throw new AssertionError("accepted stack beyond requested size");
      } catch (java.io.IOException expected) { }
    } finally { Files.deleteIfExists(capture); }
    JsonObject frame = new JsonObject();
    frame.addProperty("className", "com.example.networktest.MainActivity");
    frame.addProperty("methodName", "onCreate");
    frame.addProperty("lineNumber", "42");
    if (!JavaSourceView.remoteOrigin("/data/app/~~a/b==/base.apk!classes2.dex").equals("/data/app/~~a/b==/base.apk")
        || !JavaSourceView.remoteOrigin("/data/app/a;touch x.apk").isEmpty())
      throw new AssertionError("APK origin handling");
    String source = "// public 123\npublic class Sample {\n/* 42 */ void onCreate() { String s = \"return 123\"; }\n}";
    String methods = "class Sample {\n  void caller() { onCreate(); }\n  public void onCreate() {\n    /* 41 */ work();\n  }\n  public void onCreate(int value) {\n    /* 42 */ work();\n  }\n}\n";
    if (JavaSourceView.sourceOffset(methods, frame) != methods.indexOf("  public void onCreate(int"))
      throw new AssertionError("method declaration/overload navigation");
    SwingUtilities.invokeAndWait(() -> {
      try { checkHighlightedText(); }
      catch (Exception ex) { throw new RuntimeException(ex); }
      JTextPane pane = new JTextPane();
      JavaSourceView.highlight(pane, source);
      try {
        JavaSourceView.markMethod(pane, JavaSourceView.sourceOffset(source, frame));
        if (pane.getHighlighter().getHighlights().length != 1) throw new AssertionError("method background missing");
      } catch (BadLocationException ex) { throw new RuntimeException(ex); }
      JavaSourceView.SourcePane wide = new JavaSourceView.SourcePane();
      wide.setText("public class " + "LongName".repeat(100) + " {}\n");
      wide.setSize(new java.awt.Dimension(200, 100));
      if (wide.getScrollableTracksViewportWidth() || wide.getWidth() <= 200) throw new AssertionError("source wraps to viewport");
      StyledDocument doc = pane.getStyledDocument();
      Color comment = StyleConstants.getForeground(doc.getCharacterElement(3).getAttributes());
      Color keyword = StyleConstants.getForeground(doc.getCharacterElement(source.indexOf("public class")).getAttributes());
      Color literal = StyleConstants.getForeground(doc.getCharacterElement(source.indexOf("return 123")).getAttributes());
      if (comment.equals(keyword) || keyword.equals(literal) || comment.equals(literal))
        throw new AssertionError("syntax highlighting token precedence");
      DebuggerView view = new DebuggerView();
      view.memoryRows.addRow(new Object[] {"0x1000", "+0x0", "0x2000", "", ""});
      Color addressColor = view.memory.getCellRenderer(0, 0).getTableCellRendererComponent(view.memory, "0x1000", false, false, 0, 0).getForeground();
      Color valueColor = view.memory.getCellRenderer(0, 2).getTableCellRendererComponent(view.memory, "0x2000", false, false, 0, 2).getForeground();
      if (addressColor.equals(valueColor)) throw new AssertionError("address/value colors are identical");
      view.setEventMode(1);
      JsonObject pc = new JsonObject();
      pc.addProperty("syscallPc", "0x1234");
      view.snapshot = pc;
      view.instructionRows.addRow(new Object[] {"0x0000000000001234", "0f05", "syscall", ""});
      java.awt.Component cell = view.instructions.getCellRenderer(0, 0).getTableCellRendererComponent(view.instructions, "0x1234", true, false, 0, 0);
      if (cell.getBackground().equals(view.instructions.getSelectionBackground())) throw new AssertionError("selected PC background lost");
      for (int i = 0; i < view.stackTabs.getTabCount(); i++)
        if (view.stackTabs.getTitleAt(i).equals("Symbols")) throw new AssertionError("Symbols tab still present");
      FridaView stacks = new FridaView();
      JsonObject event = new JsonObject();
      JsonObject java = new JsonObject();
      JsonArray frames = new JsonArray();
      frames.add(frame);
      java.add("frames", frames);
      event.add("java", java);
      event.add("nativeFrames", new JsonArray());
      event.addProperty("result", 1);
      event.addProperty("capturedAtEpochMs", 1000);
      stacks.display(event);
      JButton sourceIcon = (JButton) stacks.javaTable.getCellRenderer(0, 4).getTableCellRendererComponent(stacks.javaTable, "Show", false, false, 0, 4);
      if (!stacks.javaTable.getColumnName(4).equals("Source") || sourceIcon.getIcon() == null
          || !sourceIcon.getText().isEmpty() || sourceIcon.getToolTipText() == null)
        throw new AssertionError("source icon or column label missing");
      if (stacks.javaTable.getColumnCount() != 5 || !stacks.javaFrames.isCellEditable(0, 4)
          || stacks.javaFrames.isCellEditable(0, 1) || !stacks.javaDetails.get(0).equals(frame))
        throw new AssertionError("Java frame Show action metadata");
    });
    if (args.length >= 3) {
      String output = JavaSourceView.decompile(args[1], frame, Path.of(args[2]));
      if (!output.contains("MainActivity") || !output.contains("onCreate"))
        throw new AssertionError("jadx source missing");
      if (JavaSourceView.sourceOffset(output, frame) < 0)
        throw new AssertionError("jadx method declaration not found");
      if (args.length >= 4) {
        frame.addProperty("origin", args[3]);
        String remote = JavaSourceView.decompile(args[1], frame, null);
        if (!remote.contains("MainActivity")) throw new AssertionError("ADB source missing");
      }
      System.out.println("PASS: real jadx CLI decompilation");
    }
    System.out.println("PASS: 4/16 KiB compatibility, origin validation, syntax colors, original-line navigation, Java Show metadata, no Symbols tab");
  }
}
