package ebpfproxy;

import com.google.gson.*;
import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.table.*;

final class FridaView extends JPanel {
  final JButton capture = UiLayout.button("Capture next I/O");
  final JLabel status = new JLabel("Select an I/O event");
  final DefaultTableModel nativeFrames = DebuggerView.model("Frame", "Address", "Symbol", "Path");
  final DefaultTableModel javaFrames = new DefaultTableModel(new String[] {"Frame", "Method", "File", "Line", "Source"}, 0) {
    public boolean isCellEditable(int row, int column) { return column == 4; }
  };
  final java.util.List<JsonObject> javaDetails = new ArrayList<>();
  final JTable javaTable = DebuggerView.table(javaFrames);
  final JLabel javaStatus =
      new JLabel("Java stack is collected on the target TID in the exception handler");
  JsonObject snapshot;
  boolean busy;
  FridaView() {
    super(new BorderLayout(4, 4));
    FridaLookup.initialize();
    JPanel header = new JPanel(new BorderLayout());
    header.add(capture, BorderLayout.WEST);
    header.add(status);
    add(header, BorderLayout.NORTH);
    JTabbedPane stacks = new JTabbedPane();
    stacks.addTab("Native Stack", columns(nativeFrames, 55, 180, 450, 500));
    JPanel java = new JPanel(new BorderLayout());
    javaTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
    javaTable.setRowHeight(Math.max(24, javaTable.getRowHeight()));
    int[] widths = {55, 500, 220, 70, 75};
    for (int i = 0; i < widths.length; i++)
      javaTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
    javaTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
      public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
          boolean focus, int row, int col) {
        super.getTableCellRendererComponent(table, value, selected, focus, row, col);
        setForeground(selected ? table.getSelectionForeground()
            : col == 1 ? new Color(45, 85, 175) : col == 2 ? new Color(35, 125, 85) : table.getForeground());
        return this;
      }
    });
    JButton sourceButton = sourceButton();
    javaTable.getColumnModel().getColumn(4).setCellRenderer((table, value, selected, focus, row, col) -> sourceButton);
    class ShowEditor extends AbstractCellEditor implements TableCellEditor {
      final JButton button = sourceButton();
      JsonObject frame;
      ShowEditor() {
        button.addActionListener(e -> {
          JsonObject target = frame.deepCopy();
          fireEditingStopped();
          JavaSourceView.show(FridaView.this, target);
        });
      }
      public Object getCellEditorValue() { return "Show"; }
      public Component getTableCellEditorComponent(JTable table, Object value, boolean selected, int row, int col) {
        frame = javaDetails.get(table.convertRowIndexToModel(row));
        return button;
      }
    }
    javaTable.getColumnModel().getColumn(4).setCellEditor(new ShowEditor());
    java.add(DebuggerView.scroll(javaTable));
    java.add(javaStatus, BorderLayout.SOUTH);
    stacks.addTab("Java Stack", java);
    add(stacks);
    capture.setToolTipText("Wait up to 15 seconds for the next completed TCP I/O on this TID. This "
                           + "actively attaches Frida and sends one SIGTRAP; it does not recover "
                           + "an old event or follow async scheduling.");
    capture.addActionListener(e -> start());
    capture.setEnabled(false);
  }
  static JButton sourceButton() {
    JButton button = new JButton(new Icon() {
      public int getIconWidth() { return 18; }
      public int getIconHeight() { return 18; }
      public void paintIcon(Component c, Graphics graphics, int x, int y) {
        Graphics2D g = (Graphics2D) graphics.create();
        g.translate(x, y);
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(new Color(45, 85, 175));
        g.setStroke(new BasicStroke(1.3f));
        g.drawPolyline(new int[] {11, 3, 3, 15, 15, 11, 11, 15}, new int[] {1, 1, 17, 17, 5, 1, 5, 5}, 8);
        g.drawPolyline(new int[] {7, 5, 7}, new int[] {8, 10, 12}, 3);
        g.drawPolyline(new int[] {11, 13, 11}, new int[] {8, 10, 12}, 3);
        g.dispose();
      }
    });
    button.setMargin(new Insets(1, 4, 1, 4));
    button.setToolTipText("Show decompiled source");
    button.getAccessibleContext().setAccessibleName("Show decompiled source");
    return button;
  }
  static JScrollPane columns(DefaultTableModel model, int... widths) {
    JTable table = DebuggerView.table(model);
    table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
    for (int i = 0; i < widths.length; i++)
      table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
    return DebuggerView.scroll(table);
  }
  String key() {
    return snapshot == null ? "" : SymbolLookup.key(snapshot);
  }
  void select(JsonObject value) {
    String old = key();
    snapshot = value;
    if (!old.equals(key())) {
      if (javaTable.isEditing()) javaTable.getCellEditor().cancelCellEditing();
      nativeFrames.setRowCount(0);
      javaFrames.setRowCount(0);
      javaDetails.clear();
      status.setText("Next I/O on selected TID; separate from historical event");
      javaStatus.setText(
          "Java stack at syscall exit; requires a Java environment on the target TID");
    }
    capture.setEnabled(!busy && snapshot != null
        && Set.of("send", "receive").contains(DebuggerView.str(snapshot, "operation")));
  }
  void start() {
    if (busy || snapshot == null)
      return;
    JsonObject target = snapshot.deepCopy();
    String selected = key();
    busy = true;
    capture.setEnabled(false);
    status.setText("Waiting for next TCP " + DebuggerView.str(target, "operation") + " on TID "
        + DebuggerView.str(target, "tid") + "...");
    new SwingWorker<JsonObject, Void>() {
      protected JsonObject doInBackground() throws Exception {
        return FridaLookup.request(target, "capture", Collections.emptySet());
      }
      protected void done() {
        busy = false;
        select(snapshot);
        if (!selected.equals(key()))
          return;
        try {
          display(get());
        } catch (Exception e) {
          Throwable cause = e.getCause() == null ? e : e.getCause();
          status.setText("Capture unavailable: " + cause.getMessage());
          status.setToolTipText(cause.getMessage());
        }
      }
    }.execute();
  }
  void display(JsonObject event) {
    if (javaTable.isEditing()) javaTable.getCellEditor().cancelCellEditing();
    nativeFrames.setRowCount(0);
    javaFrames.setRowCount(0);
    javaDetails.clear();
    int index = 0;
    for (JsonElement e : event.getAsJsonArray("nativeFrames")) {
      JsonObject f = e.getAsJsonObject();
      nativeFrames.addRow(new Object[] {index++,
          DebuggerView.displayAddress(DebuggerView.str(f, "address")),
          nativeSymbol(f), DebuggerView.str(f, "module")});
    }
    JsonObject javaData = event.getAsJsonObject("java");
    index = 0;
    for (JsonElement e : javaData.getAsJsonArray("frames")) {
      JsonObject f = e.getAsJsonObject();
      javaDetails.add(f.deepCopy());
      javaFrames.addRow(new Object[] {index++,
          DebuggerView.str(f, "className") + "." + DebuggerView.str(f, "methodName"),
          DebuggerView.str(f, "fileName"), DebuggerView.str(f, "lineNumber"), "Show"});
    }
    javaStatus.setText(DebuggerView.str(javaData, "source") + " · "
        + (javaData.has("error") ? DebuggerView.str(javaData, "error")
                                 : DebuggerView.str(javaData, "method")));
    long result = event.get("result").getAsLong();
    String outcome =
        result < 0 ? "Error " + result : result + " " + DebuggerView.str(event, "resultUnit");
    String time = java.time.Instant.ofEpochMilli(event.get("capturedAtEpochMs").getAsLong())
                      .atZone(java.time.ZoneId.systemDefault())
                      .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss.SSS"));
    status.setText(time + " · TID " + DebuggerView.str(event, "tid") + " · " + outcome);
    status.setToolTipText(DebuggerView.str(event, "scope")
        + "; skipped readiness/restart/unsupported calls: " + DebuggerView.str(event, "skipped"));
  }
  static String nativeSymbol(JsonObject frame) {
    return DebuggerView.str(frame, "symbol").replaceFirst("(?i)^0x[0-9a-f]+(?:\\s+|$)", "");
  }
}
