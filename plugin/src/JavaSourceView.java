package ebpfproxy;

import com.google.gson.JsonObject;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.*;
import javax.swing.*;
import javax.swing.text.*;

final class JavaSourceView {
  static final Pattern TOKENS = Pattern.compile(
      "(?<comment>//[^\\n]*|/\\*[\\s\\S]*?\\*/)|(?<string>\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*')"
      + "|(?<keyword>\\b(?:abstract|assert|boolean|break|byte|case|catch|char|class|const|continue|default|do|double|else|enum|extends|final|finally|float|for|if|implements|import|instanceof|int|interface|long|native|new|null|package|private|protected|public|return|short|static|strictfp|super|switch|synchronized|this|throw|throws|transient|true|false|try|void|volatile|while|record|var|yield)\\b)"
      + "|(?<number>\\b(?:0x[0-9a-fA-F]+|[0-9]+(?:\\.[0-9]+)?)[lLfFdD]?\\b)"
      + "|(?<annotation>@[\\w.]+)|(?<method>\\b[A-Za-z_$][\\w$]*(?=\\s*\\())"
      + "|(?<type>\\b[A-Z][\\w$]*\\b)|(?<operator>[-+*/%=!<>?:&|^~]+)");

  static final class SourcePane extends JTextPane {
    public boolean getScrollableTracksViewportWidth() { return false; }
    public void setSize(Dimension size) {
      super.setSize(new Dimension(Math.max(size.width, getPreferredSize().width), size.height));
    }
  }

  static void show(Component parent, JsonObject frame) {
    if (AnalyzerSettings.jadxPath().isBlank()) {
      AnalyzerSettings.show(parent);
      if (AnalyzerSettings.jadxPath().isBlank()) return;
    }
    new Viewer(parent, frame).open();
  }
  static final class Viewer {
    final JsonObject frame;
    final JDialog dialog;
    final JTextPane code = new SourcePane();
    final JLabel status = new JLabel("Loading...");
    final JButton local = UiLayout.button("Open APK / DEX...");
    final JTextArea numbers = new JTextArea();
    SwingWorker<String, Void> worker;
    Viewer(Component parent, JsonObject frame) {
      this.frame = frame.deepCopy();
      dialog = new JDialog(SwingUtilities.getWindowAncestor(parent), "Java Source", Dialog.ModalityType.MODELESS);
      dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
      JPanel panel = new JPanel(new BorderLayout(6, 6));
      JPanel heading = new JPanel(new BorderLayout());
      heading.add(new JLabel(DebuggerView.str(frame, "className") + "." + DebuggerView.str(frame, "methodName")
          + "  |  captured line " + DebuggerView.str(frame, "lineNumber")));
      heading.add(local, BorderLayout.EAST);
      panel.add(heading, BorderLayout.NORTH);
      code.setEditable(false);
      code.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
      numbers.setFont(code.getFont());
      numbers.setEditable(false);
      numbers.setForeground(Color.GRAY);
      numbers.setBackground(new Color(245, 245, 245));
      JScrollPane scroll = new JScrollPane(code);
      scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
      scroll.setRowHeaderView(numbers);
      panel.add(scroll);
      panel.add(status, BorderLayout.SOUTH);
      dialog.setContentPane(panel);
      dialog.setSize(1000, 720);
      dialog.setLocationRelativeTo(parent);
      local.addActionListener(e -> choose());
      dialog.addWindowListener(new WindowAdapter() {
        public void windowClosed(WindowEvent e) {
          if (worker != null) worker.cancel(true);
        }
      });
    }
    void open() {
      dialog.setVisible(true);
      if (remoteOrigin(DebuggerView.str(frame, "origin")).isEmpty()) {
        status.setText("No APK/DEX origin in this frame. Select its APK, DEX or JAR with Open APK / DEX...");
      } else load(null);
    }
    void choose() {
      JFileChooser picker = new JFileChooser();
      picker.setDialogTitle("Select the APK / DEX / JAR containing this class");
      if (picker.showOpenDialog(dialog) == JFileChooser.APPROVE_OPTION)
        load(picker.getSelectedFile().toPath());
    }
    void load(Path input) {
      if (worker != null && !worker.isDone()) return;
      local.setEnabled(false);
      status.setText(input == null ? "Reading APK/DEX from device and running jadx..." : "Running jadx...");
      String executable = AnalyzerSettings.jadxPath();
      worker = new SwingWorker<>() {
        protected String doInBackground() throws Exception { return decompile(executable, frame, input); }
        protected void done() {
          if (!dialog.isDisplayable()) return;
          local.setEnabled(true);
          try {
            String source = get();
            highlight(code, source);
            StringBuilder gutter = new StringBuilder();
            int lines = source.split("\n", -1).length;
            for (int i = 1; i <= lines; i++) gutter.append(i).append("  \n");
            numbers.setText(gutter.toString());
            int at = sourceOffset(source, frame);
            markMethod(code, at);
            code.setCaretPosition(Math.max(0, at));
            SwingUtilities.invokeLater(() -> {
              try { code.scrollRectToVisible(code.modelToView2D(Math.max(0, at)).getBounds()); }
              catch (BadLocationException ignored) { }
            });
            status.setText(at < 0 ? "Method declaration not found in decompiled source."
                : "Highlighted: method declaration. Gutter numbers refer to decompiled source; overloaded methods use captured debug lines when available.");
          } catch (Exception ex) {
            Throwable cause = ex.getCause() == null ? ex : ex.getCause();
            status.setText("Unable to show source. Use Open APK / DEX... or check Settings.");
            code.setText(cause.toString());
            numbers.setText("");
          }
        }
      };
      worker.execute();
    }
  }
  static String remoteOrigin(String origin) {
    int archive = origin.indexOf('!');
    if (archive >= 0) origin = origin.substring(0, archive);
    return origin.matches("/[A-Za-z0-9_./@~+=-]+\\.(apk|dex|jar)") ? origin : "";
  }
  static List<String> jadxCommand(String executable) throws IOException {
    Path path = Path.of(executable).toAbsolutePath();
    if (!Files.isRegularFile(path)) throw new IOException("jadx CLI not found: " + path);
    String java = Path.of(System.getProperty("java.home"), "bin",
        System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java").toString();
    if (path.toString().toLowerCase(Locale.ROOT).endsWith(".bat")) {
      // Use the distribution's Java entry point, avoiding cmd.exe argument expansion.
      Path lib = path.getParent().getParent().resolve("lib");
      if (!Files.isDirectory(lib)) throw new IOException("Select bin/jadx.bat from the full jadx CLI distribution (lib/ required)");
      return new ArrayList<>(List.of(java, "-cp", lib + File.separator + "*", "jadx.cli.JadxCLI"));
    }
    if (path.toString().endsWith(".jar")) return new ArrayList<>(List.of(java, "-jar", path.toString()));
    return new ArrayList<>(List.of(path.toString()));
  }
  static String decompile(String executable, JsonObject frame, Path local) throws Exception {
    String className = DebuggerView.str(frame, "className");
    if (!className.matches("[\\p{L}_$][\\p{L}\\p{N}_$]*(?:\\.[\\p{L}_$][\\p{L}\\p{N}_$]*)*"))
      throw new IOException("No supported Java class name in frame");
    Path temp = Files.createTempDirectory("ebpf-jadx-");
    try {
      if (local == null) {
        String remote = remoteOrigin(DebuggerView.str(frame, "origin"));
        if (remote.isEmpty()) throw new IOException("No APK/DEX path; choose a local file");
        local = temp.resolve("input" + remote.substring(remote.lastIndexOf('.')));
        run(List.of(System.getProperty("packetproxy.adb", "adb"), "-s",
            System.getProperty("packetproxy.adb.serial", "emulator-5554"), "pull", remote, local.toString()), temp, 60);
      }
      Path output = temp.resolve("source.java");
      List<String> command = jadxCommand(executable);
      command.addAll(List.of("--single-class", className, "--single-class-output", output.toString(),
          "--add-debug-lines", "--no-inline-anonymous", "--no-move-inner-classes", "-r", "-j", "2", local.toAbsolutePath().toString()));
      run(command, temp, 120);
      if (!Files.isRegularFile(output)) throw new IOException("Class not found in this APK/DEX. Try its split APK or framework JAR.");
      if (Files.size(output) > 1024 * 1024) throw new IOException("Source exceeds the 1 MiB viewer limit");
      return Files.readString(output);
    } finally {
      // Only this operation's newly created temporary directory is cleaned up.
      try (var paths = Files.walk(temp)) {
        for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
      }
    }
  }
  static void run(List<String> args, Path directory, int seconds) throws Exception {
    Path log = directory.resolve("process.log");
    Process process = new ProcessBuilder(args).redirectErrorStream(true).redirectOutput(log.toFile()).start();
    try {
      if (!process.waitFor(seconds, TimeUnit.SECONDS)) throw new IOException("Command timed out: " + args.get(0));
      if (process.exitValue() != 0) {
        String message;
        try (InputStream input = Files.newInputStream(log)) {
          message = new String(input.readNBytes(8192), StandardCharsets.UTF_8);
        }
        throw new IOException(args.get(0) + " failed:\n" + message);
      }
    } finally {
      if (process.isAlive()) {
        process.descendants().forEach(ProcessHandle::destroyForcibly);
        process.destroyForcibly();
        process.waitFor(5, TimeUnit.SECONDS);
      }
    }
  }
  static int sourceOffset(String source, JsonObject frame) {
    // Mask comments and strings so calls or braces inside them cannot be declarations.
    StringBuilder masked = new StringBuilder(source);
    Matcher tokens = TOKENS.matcher(source);
    while (tokens.find()) if (tokens.group("comment") != null || tokens.group("string") != null)
      for (int i = tokens.start(); i < tokens.end(); i++)
        if (masked.charAt(i) != '\n' && masked.charAt(i) != '\r') masked.setCharAt(i, ' ');
    String method = DebuggerView.str(frame, "methodName");
    boolean constructor = method.equals("<init>");
    if (method.equals("<init>")) {
      String name = DebuggerView.str(frame, "className");
      method = name.substring(Math.max(name.lastIndexOf('.'), name.lastIndexOf('$')) + 1);
    }
    String modifiers = "(?:(?:public|protected|private|static|final|synchronized|native|abstract|strictfp|default)[ \\t]+)*";
    Matcher match = Pattern.compile("(?m)^[ \\t]*" + modifiers
        + (constructor ? "" : "(?:<[^>\\n]+>[ \\t]+)?[\\w.$<>\\[\\], ?]+[ \\t]+")
        + Pattern.quote(method) + "[ \\t]*\\(").matcher(masked);
    int first = -1, debugAt = -1;
    String line = DebuggerView.str(frame, "lineNumber");
    if (line.matches("[1-9][0-9]*")) {
      Matcher debug = Pattern.compile("/\\*\\s*" + line + "\\s*\\*/").matcher(source);
      if (debug.find()) debugAt = debug.start();
    }
    while (match.find()) {
      String declaration = masked.substring(match.start(), match.end());
      if (declaration.matches("(?s).*\\b(return|throw|new)\\b.*")) continue;
      int at = match.end(), depth = 1;
      while (at < masked.length() && depth > 0) {
        char c = masked.charAt(at++);
        if (c == '(') depth++; else if (c == ')') depth--;
      }
      while (at < masked.length() && masked.charAt(at) != '{' && masked.charAt(at) != ';') at++;
      if (at == masked.length()) continue;
      int start = match.start();
      if (first < 0) first = start;
      if (masked.charAt(at) == '{') {
        int end = at + 1;
        depth = 1;
        while (end < masked.length() && depth > 0) {
          char c = masked.charAt(end++);
          if (c == '{') depth++; else if (c == '}') depth--;
        }
        if (debugAt >= start && debugAt < end) return start;
      }
    }
    return first;
  }
  static void markMethod(JTextPane pane, int at) throws BadLocationException {
    DefaultHighlighter highlighter = new DefaultHighlighter();
    // Paint the row once, before any syntax-colored glyphs. A layered painter is
    // invoked for every styled run and would erase text painted by earlier runs.
    highlighter.setDrawsLayeredHighlights(false);
    pane.setHighlighter(highlighter);
    if (at < 0) return;
    int end = pane.getText().indexOf('\n', at);
    if (end < 0) end = pane.getDocument().getLength();
    pane.getHighlighter().addHighlight(at, end, new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 240, 185)) {
      public void paint(Graphics g, int start, int finish, Shape bounds, JTextComponent component) {
        try {
          Rectangle row = component.modelToView2D(start).getBounds();
          row.x = 0;
          row.width = component.getWidth();
          g.setColor(getColor());
          g.fillRect(row.x, row.y, row.width, row.height);
        } catch (BadLocationException ignored) { }
      }
    });
  }
  static void highlight(JTextPane pane, String source) {
    pane.setText(source);
    StyledDocument doc = pane.getStyledDocument();
    SimpleAttributeSet normal = new SimpleAttributeSet();
    StyleConstants.setForeground(normal, new Color(35, 40, 50));
    doc.setCharacterAttributes(0, source.length(), normal, true);
    Matcher matcher = TOKENS.matcher(source);
    while (matcher.find()) {
      SimpleAttributeSet style = new SimpleAttributeSet();
      Color color = matcher.group("comment") != null ? new Color(100, 115, 100)
          : matcher.group("string") != null ? new Color(30, 125, 65)
          : matcher.group("keyword") != null ? new Color(125, 45, 155)
          : matcher.group("annotation") != null ? new Color(150, 100, 15)
          : matcher.group("method") != null ? new Color(35, 85, 175)
          : matcher.group("type") != null ? new Color(20, 125, 135)
          : matcher.group("operator") != null ? new Color(150, 65, 45) : new Color(30, 90, 180);
      StyleConstants.setForeground(style, color);
      StyleConstants.setBold(style, matcher.group("keyword") != null);
      doc.setCharacterAttributes(matcher.start(), matcher.end() - matcher.start(), style, true);
    }
  }
}
