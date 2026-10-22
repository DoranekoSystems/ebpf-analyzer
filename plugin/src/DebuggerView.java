package ebpfproxy;

import com.google.gson.*;
import java.awt.*;
import java.awt.event.*;
import java.nio.*;
import java.util.*;
import javax.swing.*;
import javax.swing.table.*;

/** Offline debugger view. Dereferences only bytes belonging to this event. */
public final class DebuggerView extends JPanel {
  final DefaultTableModel registerRows = model("Register", "Value");
  final DefaultTableModel memoryRows =
      model("Address", "Offset", "Value (64-bit)", "References", "Text");
  final DefaultTableModel frameRows =
      model("Frame", "PC / Return Address", "Stack Address", "Source");
  final JTable registers = table(registerRows), memory = table(memoryRows),
               frames = table(frameRows);
  final JLabel title = new JLabel("Select an event"),
               unwindStatus = new JLabel("No stack available");
  final JTabbedPane stackTabs = new JTabbedPane();
  byte[] data = new byte[0];
  long base;
  final JComboBox<String> symbolMode = new JComboBox<>(new String[] {"None", "Manual"});
  final JLabel symbolLabel = new JLabel("Symbols:");
  final JButton resolve = UiLayout.button("Resolve");
  final JLabel symbolStatus = new JLabel(" ");
  JsonObject snapshot;
  boolean resolving;
  boolean externalMode;
  void setEventMode(int mode) {
    externalMode = true;
    symbolMode.setVisible(false);
    symbolLabel.setVisible(false);
    symbolMode.setSelectedIndex(mode == 0 ? 0 : 1);
    fridaView.capture.setVisible(false);
  }
  Component recordedTab;
  void showRecorded(JsonObject event) {
    if (stackTabs.indexOfComponent(fridaView) >= 0) recordedTab = stackTabs.getSelectedComponent();
    showSnapshot(event);
    if (event != null) {
      if (stackTabs.indexOfComponent(fridaView) < 0) stackTabs.addTab("Captured Stacks", fridaView);
      fridaView.display(event);
      Component preferred = recordedTab == null ? fridaView : recordedTab;
      if (stackTabs.indexOfComponent(preferred) >= 0) stackTabs.setSelectedComponent(preferred);
    }
  }

  final DefaultTableModel instructionRows = model("Address", "Bytes", "Instruction", "Comment");
  final JTable instructions = table(instructionRows);
  final JPanel disassemblyPanel = new JPanel(new BorderLayout());
  final JLabel instructionSource = new JLabel("ELF file"),
               instructionStatus = new JLabel("Select a Call Stack frame, then open Disassembly");
  final JScrollPane codeScroll = scroll(instructions);
  final JButton earlierCode = UiLayout.button("Earlier"), moreCode = UiLayout.button("More"), goPC = UiLayout.button("Go to PC");
  final java.util.List<Object[]> localFrames = new ArrayList<>();
  String localStop = "", nextCode = "", previousCode = "";
  boolean paging;
  final FridaView fridaView = new FridaView();
  String lookupKey() {
    return snapshotKey() + (symbolMode.getSelectedIndex() == 2 ? "/frida" : "");
  }

  public DebuggerView() {
    super(new BorderLayout(4, 4));
    JPanel heading = new JPanel(new BorderLayout());
    heading.add(title, BorderLayout.NORTH);
    JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
    toolbar.add(symbolLabel);
    UiLayout.combo(symbolMode);
    toolbar.add(symbolMode);
    toolbar.add(resolve);
    toolbar.add(symbolStatus);
    heading.add(UiLayout.horizontal(toolbar));
    add(heading, BorderLayout.NORTH);
    resolve.setEnabled(false);
    resolve.addActionListener(e -> resolveSymbols());
    JPanel codeTop = new JPanel(new BorderLayout());
    codeTop.add(instructionSource);
    JPanel codeButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
    codeButtons.add(earlierCode);
    codeButtons.add(goPC);
    codeButtons.add(moreCode);
    codeTop.add(codeButtons, BorderLayout.EAST);
    disassemblyPanel.add(codeTop, BorderLayout.NORTH);
    disassemblyPanel.add(codeScroll);
    disassemblyPanel.add(instructionStatus, BorderLayout.SOUTH);
    earlierCode.setEnabled(false);
    earlierCode.addActionListener(e -> loadCode(true));
    moreCode.setEnabled(false);
    moreCode.addActionListener(e -> loadMoreCode());
    goPC.addActionListener(e -> {
      if (snapshot == null)
        return;
      String pc = str(snapshot, "syscallPc");
      for (int i = 0; i < instructionRows.getRowCount(); i++)
        if (instructionRows.getValueAt(i, 0).toString().equalsIgnoreCase(pc)) {
          instructions.setRowSelectionInterval(i, i);
          instructions.scrollRectToVisible(instructions.getCellRect(i, 0, true));
          return;
        }
    });
    codeScroll.addMouseWheelListener(e -> {
      if (e.getWheelRotation() < 0 && nearCodeStart())
        loadCode(true);
      if (e.getWheelRotation() > 0 && nearCodeEnd())
        loadMoreCode();
    });
    codeScroll.getVerticalScrollBar().addAdjustmentListener(e -> {
      if (e.getValueIsAdjusting() && nearCodeStart()) loadCode(true);
      if (e.getValueIsAdjusting() && nearCodeEnd())
        loadMoreCode();
    });
    instructions.addKeyListener(new KeyAdapter() {
      public void keyPressed(KeyEvent e) {
        if ((e.getKeyCode() == KeyEvent.VK_UP || e.getKeyCode() == KeyEvent.VK_PAGE_UP || e.getKeyCode() == KeyEvent.VK_HOME) && nearCodeStart()) loadCode(true);
        if ((e.getKeyCode() == KeyEvent.VK_DOWN || e.getKeyCode() == KeyEvent.VK_PAGE_DOWN
                || e.getKeyCode() == KeyEvent.VK_END)
            && nearCodeEnd())
          loadMoreCode();
      }
    });
    instructions.setShowHorizontalLines(false);
    instructions.setRowHeight(Math.max(20, instructions.getRowHeight()));
    instructions.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
      public Component getTableCellRendererComponent(
          JTable t, Object value, boolean selected, boolean focus, int row, int col) {
        super.getTableCellRendererComponent(t, value, selected, focus, row, col);
        setFont(t.getFont());
        setForeground(selected ? t.getSelectionForeground() : Color.BLACK);
        setBackground(selected ? t.getSelectionBackground() : Color.WHITE);
        boolean pc = snapshot != null
            && sameAddress(t.getValueAt(row, 0).toString(), str(snapshot, "syscallPc"));
        if (pc && col == 0) {
          setBackground(new Color(225, 242, 224));
          setForeground(new Color(25, 80, 45));
        }
        if (col == 0) {
          setText((pc ? "\u25b6 " : "  ") + displayAddress(value.toString()));
          if (!selected)
            setForeground(new Color(65, 90, 130));
        }
        if (col == 1) {
          setText(value.toString().replaceAll("(..)(?!$)", "$1 ").toUpperCase(Locale.ROOT));
          if (!selected)
            setForeground(Color.GRAY);
        }
        if (col == 2 && !selected) {
          String op = value.toString().split(" ")[0];
          setForeground(op.startsWith("j") || op.equals("call")  ? new Color(30, 75, 185)
                  : op.startsWith("ret") || op.equals("syscall") ? new Color(150, 50, 130)
                                                                 : Color.BLACK);
        }
        if (col == 3 && !selected)
          setForeground(new Color(70, 120, 75));
        return this;
      }
    });
    instructions.getColumnModel().getColumn(0).setPreferredWidth(170);
    instructions.getColumnModel().getColumn(1).setPreferredWidth(170);
    instructions.getColumnModel().getColumn(2).setPreferredWidth(280);
    symbolMode.addActionListener(e -> {
      applySymbols();
      autoResolvePending = symbolMode.getSelectedIndex() != 0;
      autoLiveKey = !externalMode && symbolMode.getSelectedIndex() == 2 ? snapshotKey() : "";
      autoResolve();
    });
    JPanel callStack = new JPanel(new BorderLayout());
    callStack.add(scroll(frames));
    callStack.add(unwindStatus, BorderLayout.SOUTH);
    stackTabs.addTab("Call Stack", callStack);
    stackTabs.addTab("Stack Memory", scroll(memory));
    stackTabs.addChangeListener(e -> SwingUtilities.invokeLater(this::refreshSelectedDisassembly));
    JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, scroll(registers), stackTabs);
    split.setResizeWeight(.38);
    add(split);
    registers.setToolTipText("Double-click a value to follow it in this event's stack memory");
    memory.setToolTipText("64-bit little-endian words. Double-click a value to follow a pointer "
                          + "within this snapshot");
    frames.setToolTipText(
        "Double-click a frame to inspect its saved frame pointer in stack memory");
    follow(registers, 1);
    follow(memory, 2);
    follow(frames, 2);
    DefaultTableCellRenderer values = new DefaultTableCellRenderer() {
      public Component getTableCellRendererComponent(JTable t, Object value, boolean selected,
          boolean focus, int row, int col) {
        super.getTableCellRendererComponent(t, value, selected, focus, row, col);
        String name = t.getColumnName(col);
        Color color = name.equals("Symbol") || name.equals("References") || name.equals("Text")
            ? new Color(35, 125, 85)
            : name.contains("Address") ? new Color(45, 85, 175)
            : name.startsWith("Value") ? new Color(155, 80, 25)
            : name.equals("Register") ? new Color(125, 45, 155) : t.getForeground();
        setForeground(selected ? t.getSelectionForeground() : color);
        return this;
      }
    };
    for (JTable t : new JTable[] {registers, memory, frames}) {
      t.setDefaultRenderer(Object.class, values);
      t.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
      for (int i = 0; i < t.getColumnCount(); i++)
        t.getColumnModel().getColumn(i).setPreferredWidth(i == 0 ? 100 : 170);
    }
    memory.getColumnModel().getColumn(0).setPreferredWidth(170);
    memory.getColumnModel().getColumn(1).setPreferredWidth(80);
    memory.getColumnModel().getColumn(3).setPreferredWidth(230);
    memory.getColumnModel().getColumn(4).setPreferredWidth(90);
  }
  static JScrollPane scroll(JTable table) {
    JScrollPane pane = new JScrollPane(table);
    pane.setColumnHeaderView(table.getTableHeader());
    return pane;
  }
  static DefaultTableModel model(String... names) {
    return new DefaultTableModel(names, 0) {
      public boolean isCellEditable(int r, int c) {
        return false;
      }
    };
  }
  static JTable table(DefaultTableModel model) {
    JTable t = new JTable(model);
    CommunicationOrigins.styleTable(t);
    t.setFont(new Font(Font.MONOSPACED, Font.PLAIN, t.getFont().getSize()));
    t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    return t;
  }
  static String str(JsonObject o, String key) {
    return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsString() : "";
  }
  static boolean sameAddress(String a, String b) {
    try {
      return Long.parseUnsignedLong(a.replaceFirst("(?i)^0x", ""), 16)
          == Long.parseUnsignedLong(b.replaceFirst("(?i)^0x", ""), 16);
    } catch (NumberFormatException e) { return false; }
  }
  static long address(String s) {
    try {
      return Long.parseUnsignedLong(s.replaceFirst("^0x", ""), 16);
    } catch (NumberFormatException e) {
      return 0;
    }
  }
  static String hex(long n) {
    return String.format("0x%016x", n);
  }
  static String registerValue(String value) {
    try { return hex(Long.parseUnsignedLong(value.replaceFirst("(?i)^0x", ""), 16)); }
    catch (NumberFormatException ignored) { return value; }
  }
  void refreshSelectedDisassembly() {
    if (snapshot == null || stackTabs.getSelectedComponent() != disassemblyPanel) return;
    if (resolving || paging) { autoResolvePending = true; return; }
    if (!resolve.isEnabled()) return;
    JsonObject cached = SymbolLookup.get(lookupKey());
    if (cached == null || !cached.has("disassembly")
        || !sameAddress(str(cached.getAsJsonObject("disassembly"), "address"), selectedCodeAddress()))
      resolveAt(selectedCodeAddress());
  }
  static String displayAddress(String value) {
    return value.toUpperCase(Locale.ROOT).replaceFirst("^0X", "0x");
  }
  int offset(long pointer, int bytes) {
    long d = pointer - base;
    return Long.compareUnsigned(pointer, base) >= 0 && Long.compareUnsigned(d, data.length) <= 0
            && bytes <= data.length - d
        ? (int) d
        : -1;
  }
  long word(int offset) {
    return ByteBuffer.wrap(data, offset, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
  }
  void follow(JTable t, int column) {
    t.addMouseListener(new MouseAdapter() {
      public void mouseClicked(MouseEvent e) {
        if (e.getClickCount() == 2) {
          int row = t.rowAtPoint(e.getPoint());
          if (row >= 0)
            selectAddress(address(t.getValueAt(row, column).toString()));
        }
      }
    });
  }
  void selectAddress(long pointer) {
    int at = offset(pointer, 1);
    if (at < 0)
      return;
    int row = at / 8;
    stackTabs.setSelectedIndex(1);
    memory.setRowSelectionInterval(row, row);
    memory.scrollRectToVisible(memory.getCellRect(row, 0, true));
  }

  public void showSnapshot(JsonObject o) {
    snapshot = o;
    fridaView.select(o);
    localFrames.clear();
    localStop = "No stack available";
    registerRows.setRowCount(0);
    memoryRows.setRowCount(0);
    frameRows.setRowCount(0);
    data = new byte[0];
    if (o == null) {
      title.setText("Select an event");
      unwindStatus.setText("No stack available");
      applySymbols();
      return;
    }
    data = Base64.getDecoder().decode(str(o, "stack"));
    memory.setToolTipText("Captured stack: " + data.length
        + " bytes. New captures are limited to 4 KiB; deeper frames may be unavailable. Double-click to follow a saved pointer.");
    base = address(str(o, "stackBase"));
    JsonObject regs = o.getAsJsonObject("registers");
    title.setText("PID " + str(o, "pid") + "   TID " + str(o, "tid") + "   " + str(o, "operation")
        + "   " + str(o, "status"));
    Map<Long, String> markers = new HashMap<>();
    for (String key : new String[] {"rsp", "rbp"})
      if (regs.has(key))
        markers.put(address(str(regs, key)), key.toUpperCase(Locale.ROOT));
    String pc = str(o, "syscallPc");
    if (!pc.isEmpty())
      registerRows.addRow(new Object[] {"PC", registerValue(pc)});
    String[] order = {"rip", "rsp", "rbp", "rax_saved", "rbx", "rcx", "rdx", "rsi", "rdi", "r8",
        "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags", "orig_rax", "cs", "ss"};
    for (String key : order)
      if (regs.has(key)) {
        String value = str(regs, key), note = switch (key) {case "rip"->"Syscall return address";case "rsp"->"Stack pointer";case "rbp"->"Frame pointer (if used)";case "orig_rax"->"Syscall number";case "rax_saved"->"Kernel-saved RAX";case "rflags"->flags(address(value));default->"";};
            int at=offset(address(value),1);if(at>=0)note+=(note.isEmpty()?"":" · ")+"Stack +0x"+Integer.toHexString(at);
            registerRows.addRow(new Object[] {key.toUpperCase(Locale.ROOT), registerValue(value)});
        }
        if (!pc.isEmpty())
          frameRows.addRow(new Object[] {0, pc, str(regs, "rbp"), "Current syscall"});
        // RBP records are candidates, not a DWARF unwind or a scan of arbitrary words.
        long fp = address(str(regs, "rbp"));
        String stop = "Frame pointer is outside this snapshot";
        int count = 0;
        while (count < 64) {
          int at = offset(fp, 16);
          if (at < 0)
            break;
          if ((fp & 7) != 0) {
            stop = "Unaligned frame pointer";
            break;
          }
          long next = word(at), ret = word(at + 8);
          if (ret == 0) {
            stop = "No saved return address";
            break;
          }
          markers.put(fp, "RBP chain");
          markers.put(fp + 8, "Saved return address");
          frameRows.addRow(new Object[] {++count, hex(ret), hex(fp), "RBP candidate"});
          if (next == 0) {
            stop = "End of frame-pointer chain";
            break;
          }
          if (Long.compareUnsigned(next, fp) <= 0) {
            stop = "Non-increasing frame pointer";
            break;
          }
          fp = next;
          if (count == 64)
            stop = "Frame limit reached";
        }
        unwindStatus.setText(stop + " · RBP candidates; CFI unavailable");
        localStop = stop + " · Select Manual / Resolve for CFI unwinding";
        for (int i = 0; i < frameRows.getRowCount(); i++)
          localFrames.add(new Object[] {frameRows.getValueAt(i, 0), frameRows.getValueAt(i, 1),
              frameRows.getValueAt(i, 2), frameRows.getValueAt(i, 3)});
        unwindStatus.setToolTipText(
            "Functions may omit frame pointers. Candidate return addresses have not been checked "
            + "against executable mappings; this is not a complete call stack.");
        for (int i = 0; i < data.length; i += 8) {
          int length = Math.min(8, data.length - i);
          String value;
          String note = markers.getOrDefault(base + i, "");
          if (length == 8) {
            long v = word(i);
            value = hex(v);
            int to = offset(v, 1);
            if (to >= 0)
              note += (note.isEmpty() ? "" : " · ") + "→ Stack +0x" + Integer.toHexString(to);
          } else {
            StringBuilder tail = new StringBuilder();
            for (int j = 0; j < length; j++) tail.append(String.format("%02x ", data[i + j] & 255));
            value = tail.toString().trim() + " (partial)";
          }
          StringBuilder ascii = new StringBuilder();
          for (int j = 0; j < length; j++) {
            int c = data[i + j] & 255;
            ascii.append(c >= 32 && c < 127 ? (char) c : '.');
          }
          memoryRows.addRow(new Object[] {
              hex(base + i), String.format("+0x%04x", i), value, note, ascii.toString()});
        }
        applySymbols();
        if (externalMode) SwingUtilities.invokeLater(this::refreshSelectedDisassembly);
      }
    String snapshotKey() {
      try {
        return snapshot == null ? "" : SymbolLookup.key(snapshot);
      } catch (RuntimeException e) {
        return "";
      }
    }
    void applySymbols() {
      frameRows.setRowCount(0);
      for (Object[] row : localFrames) frameRows.addRow(row);
      unwindStatus.setText(localStop);
      boolean manual = symbolMode.getSelectedIndex() != 0;
      if (externalMode && snapshot != null && snapshot.has("nativeFrames")) {
        if (stackTabs.indexOfComponent(fridaView) < 0)
          stackTabs.addTab("Captured Stacks", fridaView);
      } else if (symbolMode.getSelectedIndex() == 2) {
        if (stackTabs.indexOfComponent(fridaView) < 0)
          stackTabs.addTab("Live I/O", fridaView);
      } else
        stackTabs.remove(fridaView);
      resolve.setEnabled(
          manual && snapshot != null && !resolving && !paging && !snapshotKey().isEmpty());
      if (registerRows.getColumnCount() != (manual ? 3 : 2)) {
        registerRows.setColumnIdentifiers(manual ? new String[] {"Register", "Value", "Symbol"}
                                                 : new String[] {"Register", "Value"});
        frameRows.setColumnIdentifiers(manual
                ? new String[] {"Frame", "PC / Return Address", "Stack Address", "Source", "Symbol", "Path"}
                : new String[] {"Frame", "PC / Return Address", "Stack Address", "Source"});
        for (JTable table : new JTable[] {registers, frames})
          for (int i = 0; i < table.getColumnCount(); i++)
            table.getColumnModel().getColumn(i).setPreferredWidth(i == 0 ? 100
                    : i == table.getColumnCount() - 1 && manual          ? 400
                                                                         : 170);
      }
      if (manual) {
        if (stackTabs.indexOfComponent(disassemblyPanel) < 0)
          stackTabs.addTab("Disassembly", disassemblyPanel);
      } else {
        stackTabs.remove(disassemblyPanel);
      }
      instructionRows.setRowCount(0);
      nextCode = "";
      previousCode = "";
      earlierCode.setEnabled(false);
      moreCode.setEnabled(false);
      instructionSource.setText("ELF file");
      instructionStatus.setText("Select a Call Stack frame, then open Disassembly");
      if (!manual) {
        symbolStatus.setText(" ");
        return;
      }
      for (int i = 0; i < registerRows.getRowCount(); i++) registerRows.setValueAt("", i, 2);
      for (int i = 0; i < frameRows.getRowCount(); i++) { frameRows.setValueAt("", i, 4); frameRows.setValueAt("", i, 5); }
      applyCapturedSymbols();
      JsonObject result = SymbolLookup.get(lookupKey());
      if (result == null) {
        symbolStatus.setText(
            resolving ? "Resolving..." : "Click Resolve to read current process maps");
        return;
      }
      Map<String, String> labels = new HashMap<>();
      for (JsonElement entry : result.getAsJsonArray("results")) {
        JsonObject r = entry.getAsJsonObject();
        String name = str(r, "symbol");
        labels.put(registerValue(str(r, "address")),
            name.isEmpty() ? str(r, "module") + " [" + str(r, "status") + "]"
                           : name + " · " + str(r, "module"));
      }
      for (int i = 0; i < registerRows.getRowCount(); i++)
        registerRows.setValueAt(
            labels.getOrDefault(
                registerRows.getValueAt(i, 1).toString().toLowerCase(Locale.ROOT), ""),
            i, 2);
      for (JsonElement element : result.getAsJsonArray("results")) {
        JsonObject resolved = element.getAsJsonObject();
        for (int i = 0; i < frameRows.getRowCount(); i++) {
          if (!sameAddress(frameRows.getValueAt(i, 1).toString(), str(resolved, "address"))) continue;
          frameRows.setValueAt(FridaView.nativeSymbol(resolved), i, 4);
          frameRows.setValueAt(str(resolved, "module"), i, 5);
        }
      }
      boolean truncated = false;
      for (JsonElement entry : result.getAsJsonArray("modules")) {
        JsonObject m = entry.getAsJsonObject();
        truncated |= m.get("truncated").getAsBoolean();
      }
      symbolStatus.setText("Current maps · "
          + java.time.Instant.ofEpochMilli(result.get("resolvedAtEpochMs").getAsLong())
                .atZone(java.time.ZoneId.systemDefault())
                .toLocalTime()
                .withNano(0)
          + (truncated ? " · Symbol list limited" : ""));
      symbolStatus.setToolTipText(str(result, "scope"));
      if (result.has("stackTrace")) {
        JsonObject trace = result.getAsJsonObject("stackTrace");
        frameRows.setRowCount(0);
        int index = 0;
        for (JsonElement entry : trace.getAsJsonArray("frames")) {
          JsonObject f = entry.getAsJsonObject();
          frameRows.addRow(new Object[] {index++, str(f, "pc"), str(f, "sp"),
              index == 1 ? "Current syscall" : "CFI", str(f, "symbol") + " · " + str(f, "module")});
        }
        unwindStatus.setText("CFI: " + str(trace, "stop"));
        unwindStatus.setToolTipText("Uses ELF unwind information and this event's saved stack. "
                                    + "Current maps may differ from the capture-time layout.");
      }
      applyCapturedSymbols();
      if (result.has("disassembly")) {
        JsonObject d = result.getAsJsonObject("disassembly");
        instructionSource.setText(str(d, "source"));
        instructionSource.setToolTipText(
            str(d, "boundary") + ". Linear decoding; not an execution trace or live memory.");
        instructionStatus.setText(str(d, "stop"));
        for (JsonElement entry : d.getAsJsonArray("instructions")) {
          JsonObject i = entry.getAsJsonObject();
          instructionRows.addRow(
              new Object[] {str(i, "address"), str(i, "bytes"), str(i, "text"), str(i, "symbol")});
        }
        if (instructionRows.getRowCount() > 0) {
          int row = 0;
          for (int i = 0; i < instructionRows.getRowCount(); i++)
            if (sameAddress(instructionRows.getValueAt(i, 0).toString(), str(d, "address"))) row = i;
          instructions.setRowSelectionInterval(row, row);
          final int targetRow = row;
          SwingUtilities.invokeLater(() -> {
            if (targetRow < instructions.getRowCount())
              instructions.scrollRectToVisible(instructions.getCellRect(targetRow, 0, true));
          });
        }
        previousCode = str(d, "previous");
        earlierCode.setEnabled(!previousCode.isEmpty() && !paging && instructionRows.getRowCount() < 2048);
        nextCode = str(d, "next");
        moreCode.setEnabled(!nextCode.isEmpty() && !paging && instructionRows.getRowCount() < 2048);
      }
    }
    void applyCapturedSymbols() {
      if (snapshot == null || !snapshot.has("nativeFrames") || frameRows.getColumnCount() < 6) return;
      for (JsonElement element : snapshot.getAsJsonArray("nativeFrames")) {
        JsonObject frame = element.getAsJsonObject();
        for (int i = 0; i < frameRows.getRowCount(); i++) {
          if (!sameAddress(frameRows.getValueAt(i, 1).toString(), str(frame, "address"))) continue;
          frameRows.setValueAt(FridaView.nativeSymbol(frame), i, 4);
          frameRows.setValueAt(str(frame, "module"), i, 5);
        }
      }
    }
    boolean nearCodeEnd() {
      JScrollBar bar = codeScroll.getVerticalScrollBar();
      return bar.getValue() + bar.getVisibleAmount()
          >= bar.getMaximum() - instructions.getRowHeight() * 4;
    }
    boolean nearCodeStart() { return codeScroll.getVerticalScrollBar().getValue() < instructions.getRowHeight() * 4; }
    void loadMoreCode() { loadCode(false); }
    void loadCode(boolean before) {
      if (paging || resolving || snapshot == null || symbolMode.getSelectedIndex() == 0
          || (before ? previousCode : nextCode).isEmpty() || instructionRows.getRowCount() >= 2048)
        return;
      String key = lookupKey(), next = before ? previousCode : nextCode;
      JsonObject previous = SymbolLookup.get(key);
      if (previous == null)
        return;
      JsonObject target = snapshot.deepCopy();
      paging = true;
      earlierCode.setEnabled(false);
      moreCode.setEnabled(false);
      instructionStatus.setText("Loading...");
      new SwingWorker<JsonObject, Void>() {
        protected JsonObject doInBackground() throws Exception {
          return SymbolLookup.resolve(target, Collections.emptySet(), next, previous, before);
        }
        protected void done() {
          paging = false;
          try {
            JsonObject result = get();
            if (SymbolLookup.get(key) != previous)
              return;
            JsonObject page = result.getAsJsonObject("disassembly");
            if (page == null || !str(page, "address").equals(next))
              throw new IllegalStateException("Invalid continuation");
            JsonObject merged = previous.deepCopy(), d = merged.getAsJsonObject("disassembly");
            JsonArray old = d.getAsJsonArray("instructions"), added = page.getAsJsonArray("instructions"), lines = new JsonArray();
            int room = 2048 - old.size();
            if (before) {
              for (int i = Math.max(0, added.size() - room); i < added.size(); i++) lines.add(added.get(i));
              for (JsonElement line : old) lines.add(line);
              d.addProperty("previous", lines.size() >= 2048 ? "" : str(page, "previous"));
            } else {
              for (JsonElement line : old) lines.add(line);
              for (int i = 0; i < added.size() && i < room; i++) lines.add(added.get(i));
              d.addProperty("next", lines.size() >= 2048 ? "" : str(page, "next"));
            }
            d.add("instructions", lines);
            d.addProperty("stop", lines.size() >= 2048 ? "2048-instruction view limit" : str(page, "stop"));
            SymbolLookup.put(key, merged);
            if (!key.equals(lookupKey()) || symbolMode.getSelectedIndex() == 0) return;
            Point position = codeScroll.getViewport().getViewPosition();
            int selectedRow = instructions.getSelectedRow(), inserted = lines.size() - old.size();
            instructionRows.setRowCount(0);
            for (JsonElement element : lines) {
              JsonObject line = element.getAsJsonObject();
              instructionRows.addRow(new Object[] {str(line, "address"), str(line, "bytes"), str(line, "text"), str(line, "symbol")});
            }
            if (selectedRow >= 0) instructions.setRowSelectionInterval(selectedRow + (before ? inserted : 0), selectedRow + (before ? inserted : 0));
            if (before) position.y += inserted * instructions.getRowHeight();
            SwingUtilities.invokeLater(() -> codeScroll.getViewport().setViewPosition(position));
            previousCode = str(d, "previous");
            nextCode = str(d, "next");
            instructionStatus.setText(str(d, "stop"));
            earlierCode.setEnabled(!previousCode.isEmpty() && lines.size() < 2048);
            moreCode.setEnabled(!nextCode.isEmpty() && lines.size() < 2048);
          } catch (Exception e) {
            if (key.equals(lookupKey()) && symbolMode.getSelectedIndex() != 0) {
              instructionStatus.setText("Unable to continue. Resolve again to refresh mappings.");
              instructionStatus.setToolTipText(
                  e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
              if (before) previousCode = ""; else nextCode = "";
            }
          } finally {
            autoResolve();
          }
        }
      }.execute();
    }
    boolean autoResolvePending;
    String autoLiveKey = "";
    void autoResolve() {
      if (resolving || paging)
        return;
      if (autoResolvePending) {
        autoResolvePending = false;
        if (symbolMode.getSelectedIndex() != 0 && snapshot != null && !snapshotKey().isEmpty()) {
          if (SymbolLookup.get(lookupKey()) == null)
            resolveSymbols();
          else if (!externalMode && instructionRows.getRowCount() > 0)
            stackTabs.setSelectedComponent(disassemblyPanel);
        }
      }
      if (resolving || autoLiveKey.isEmpty())
        return;
      String requested = autoLiveKey;
      autoLiveKey = "";
      if (symbolMode.getSelectedIndex() == 2 && requested.equals(snapshotKey()) && snapshot != null
          && Set.of("send", "receive").contains(str(snapshot, "operation"))) {
        stackTabs.setSelectedComponent(fridaView);
        fridaView.start();
      }
    }
    String selectedCodeAddress() {
      int row = frames.getSelectedRow();
      return row >= 0 ? frames.getValueAt(row, 1).toString() : snapshot == null ? "" : str(snapshot, "syscallPc");
    }
    void resolveSymbols() {
      resolveAt(snapshot == null ? "" : str(snapshot, "syscallPc"));
    }
    void resolveAt(String disassemblyAddress) {
      if (snapshot == null || resolving || paging)
        return;
      JsonObject target = snapshot.deepCopy();
      String key = lookupKey();
      boolean frida = symbolMode.getSelectedIndex() == 2;
      Set<String> addresses = new LinkedHashSet<>();
      for (int i = 0; i < frameRows.getRowCount(); i++)
        addresses.add(frameRows.getValueAt(i, 1).toString());
      JsonObject regs = target.getAsJsonObject("registers");
      if (regs.has("rip"))
        addresses.add(str(regs, "rip"));
      resolving = true;
      resolve.setEnabled(false);
      symbolStatus.setText("Resolving...");
      new SwingWorker<JsonObject, Void>() {
        protected JsonObject doInBackground() throws Exception {
          return frida ? FridaLookup.resolve(target, addresses, disassemblyAddress)
                       : SymbolLookup.resolve(target, addresses, disassemblyAddress);
        }
        protected void done() {
          resolving = false;
          try {
            SymbolLookup.put(key, get());
            applySymbols();
            if (!externalMode && key.equals(lookupKey()) && symbolMode.getSelectedIndex() != 0
                && !disassemblyAddress.isEmpty())
              stackTabs.setSelectedComponent(disassemblyPanel);
          } catch (Exception e) {
            applySymbols();
            if (key.equals(lookupKey()) && symbolMode.getSelectedIndex() != 0) {
              Throwable cause = e.getCause() == null ? e : e.getCause();
              symbolStatus.setText("Unable to resolve");
              symbolStatus.setToolTipText(cause.getMessage());
            }
          } finally {
            autoResolve();
          }
        }
      }.execute();
    }
    static String flags(long value) {
      String[] names = {"CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"};
      int[] bits = {0, 2, 4, 6, 7, 8, 9, 10, 11};
      StringJoiner out = new StringJoiner(" ");
      for (int i = 0; i < bits.length; i++)
        if ((value & (1L << bits[i])) != 0)
          out.add(names[i]);
      return out.toString();
    }
  }
