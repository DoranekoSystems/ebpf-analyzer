package ebpfproxy;

import com.google.gson.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.tree.*;

/** Reverse lookup of retained I/O stacks, not a trace of all function calls. */
final class ProcessBrowser extends JPanel {
  static final class Entry {
    final String kind, owner, method, offset;
    final Set<String> events = new LinkedHashSet<>();
    JsonObject frame;
    Entry(String kind, String owner, String method) { this(kind, owner, method, ""); }
    Entry(String kind, String owner, String method, String offset) { this.kind = kind; this.owner = owner; this.method = method; this.offset = offset; }
    String key() { return kind + "\n" + owner + "\n" + method + (offset.isEmpty() ? "" : "\n" + offset); }
    public String toString() {
      String label = method.isEmpty() ? owner.substring((kind.equals("module") ? owner.lastIndexOf('/') : owner.lastIndexOf('.')) + 1) : method;
      return offset.isEmpty() ? label : offset;
    }
  }
  final JTree libraries = new JTree(new DefaultMutableTreeNode("Libraries"));
  final JTree javaTree = new JTree(new DefaultMutableTreeNode("Java Sources"));
  final Map<JTree, Set<String>> expansion = new IdentityHashMap<>();
  final Map<JTree, Set<String>> knownPaths = new IdentityHashMap<>();
  final HierarchyTable libraryTable = new HierarchyTable(libraries), javaSourceTable = new HierarchyTable(javaTree);
  final JTextField search = new JTextField(24);
  final JCheckBox observedOnly = new JCheckBox("Observed in I/O stacks only", true);
  final JComboBox<String> direction = new JComboBox<>(new String[] {"Send + Receive", "Send", "Receive"});
  final JSpinner firstFrame = new JSpinner(new SpinnerNumberModel(0, 0, 4096, 1));
  final JSpinner lastFrame = new JSpinner(new SpinnerNumberModel(0, 0, 4096, 1));
  final JLabel status = new JLabel("Select a process and start Frida in Settings");
  final javax.swing.table.DefaultTableModel matches = DebuggerView.model("Time", "TID", "Operation", "Frame", "Syscall PC", "I/O Result");
  final JTable table = new JTable(matches);
  final JButton source = FridaView.sourceButton(), openEvent = UiLayout.button("Open I/O Event"), load = UiLayout.button("Load functions / methods");
  final Map<String, Entry> index = new LinkedHashMap<>();
  final Map<String, JsonObject> events = new LinkedHashMap<>();
  final List<String> matchingIds = new ArrayList<>();
  final Map<String, List<String>> members = new HashMap<>();
  final Set<String> pending = new HashSet<>();
  final Set<String> cleared = new HashSet<>();
  boolean catalogCleared;
  JsonObject catalog = new JsonObject();
  final Consumer<JsonObject> request;
  final Consumer<String> navigate;
  Entry selected;
  long pid;
  boolean rebuilding;
  final javax.swing.Timer refresh;

  ProcessBrowser(Consumer<JsonObject> request, Consumer<String> navigate) {
    super(new BorderLayout(6, 6));
    this.request = request;
    this.navigate = navigate;
    JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
    controls.add(new JLabel("Filter:")); controls.add(search); controls.add(observedOnly);
    controls.add(new JLabel("I/O:")); controls.add(direction);
    controls.add(new JLabel("Frame from:")); controls.add(firstFrame);
    controls.add(new JLabel("Depth (0 = all):")); controls.add(lastFrame);
    firstFrame.setToolTipText("Zero-based frame index, separately for native and Java stacks");
    lastFrame.setToolTipText("Number of frames from the starting index; 0 includes all remaining frames");
    JButton reload = UiLayout.button("Refresh catalog");
    reload.addActionListener(e -> { catalogCleared = false; JsonObject command = new JsonObject(); command.addProperty("action", "catalog"); request.accept(command); });
    controls.add(reload);
    JButton clear = UiLayout.button("Clear");
    clear.setToolTipText("Clear this browser only. New I/O events appear as capture continues; Refresh catalog restores the loaded inventory.");
    clear.addActionListener(e -> clear());
    JPanel clearAction = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
    clearAction.add(clear);
    JPanel heading = new JPanel(new BorderLayout());
    JPanel filters = new JPanel(new BorderLayout(6, 0));
    filters.add(UiLayout.horizontal(controls)); filters.add(clearAction, BorderLayout.EAST);
    heading.add(filters, BorderLayout.NORTH);
    heading.add(status);
    add(heading, BorderLayout.NORTH);
    JTabbedPane trees = new JTabbedPane();
    trees.addTab("Libraries", hierarchyPanel(libraryTable));
    trees.addTab("Java Sources", hierarchyPanel(javaSourceTable));
    JPanel results = new JPanel(new BorderLayout());
    JScrollPane eventScroll = DebuggerView.scroll(table);
    eventScroll.setColumnHeaderView(table.getTableHeader());
    results.add(eventScroll);
    styleTable(table);
    table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    table.getTableHeader().setReorderingAllowed(false);
    table.setDefaultRenderer(Object.class, new javax.swing.table.DefaultTableCellRenderer() {
      public Component getTableCellRendererComponent(JTable t, Object value, boolean selected, boolean focus, int row, int col) {
        super.getTableCellRendererComponent(t, value, selected, focus, row, col);
        Color bg = t.getBackground(); boolean dark = bg.getRed() + bg.getGreen() + bg.getBlue() < 384;
        setBackground(selected ? t.getSelectionBackground() : bg);
        setForeground(selected ? t.getSelectionForeground() : t.getForeground());
        setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
        setToolTipText(value == null ? null : value.toString());
        return this;
      }
    });
    table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
    int[] widths = {100, 55, 80, 120, 145, 145};
    for (int i = 0; i < widths.length; i++) table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
    table.getTableHeader().setToolTipText("Frame: zero-based matching stack indices. I/O Result: syscall return value in bytes/messages, or a negative errno.");
    JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
    actions.add(load); actions.add(source); actions.add(openEvent);
    JPanel resultHeader = new JPanel(new BorderLayout(0, 4));
    resultHeader.add(UiLayout.horizontal(actions), BorderLayout.NORTH);
    resultHeader.add(new JLabel("I/O Result: transferred bytes/messages, or an OS error code."), BorderLayout.SOUTH);
    results.add(resultHeader, BorderLayout.NORTH);
    results.add(new JLabel("Matches are captured I/O stacks. Java overloads are grouped by name."), BorderLayout.SOUTH);
    JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, trees, results);
    split.setResizeWeight(.45);
    trees.setMinimumSize(new Dimension(180, 100));
    results.setMinimumSize(new Dimension(250, 100));
    add(split);
    for (JTree tree : new JTree[] {libraries, javaTree}) {
      tree.setRootVisible(true);
      tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
      tree.addTreeSelectionListener(e -> {
        if (rebuilding) return;
        Object node = tree.getLastSelectedPathComponent();
        selected = node instanceof DefaultMutableTreeNode n && n.getUserObject() instanceof Entry value ? value : null;
        updateMatches();
      });
      tree.addTreeWillExpandListener(new TreeWillExpandListener() {
        public void treeWillExpand(TreeExpansionEvent e) {
          Object value = ((DefaultMutableTreeNode) e.getPath().getLastPathComponent()).getUserObject();
          if (!rebuilding && !observedOnly.isSelected() && value instanceof Entry entry && entry.method.isEmpty()) requestMembers(entry);
        }
        public void treeWillCollapse(TreeExpansionEvent e) { }
      });
    }
    trees.addChangeListener(e -> {
      JTree tree = trees.getSelectedIndex() == 0 ? libraries : javaTree;
      Object node = tree.getLastSelectedPathComponent();
      selected = node instanceof DefaultMutableTreeNode n && n.getUserObject() instanceof Entry value ? value : null;
      updateMatches();
    });
    load.addActionListener(e -> { if (selected != null) requestMembers(selected); });
    source.addActionListener(e -> {
      if (selected == null || !selected.kind.equals("class")) return;
      Entry owner = index.get(new Entry(selected.kind, selected.owner, "").key());
      JsonObject captured = selected.frame != null ? selected.frame : owner == null ? null : owner.frame;
      JsonObject frame = captured == null ? new JsonObject() : captured.deepCopy();
      frame.addProperty("className", selected.owner);
      frame.addProperty("methodName", selected.method);
      JavaSourceView.show(this, frame);
    });
    openEvent.addActionListener(e -> openSelected());
    table.addMouseListener(new MouseAdapter() { public void mouseClicked(MouseEvent e) { if (e.getClickCount() == 2) openSelected(); } });
    table.getSelectionModel().addListSelectionListener(e -> openEvent.setEnabled(table.getSelectedRow() >= 0));
    refresh = new javax.swing.Timer(150, e -> rebuild());
    refresh.setRepeats(false);
    search.getDocument().addDocumentListener(new DocumentListener() {
      public void insertUpdate(DocumentEvent e) { refresh.restart(); }
      public void removeUpdate(DocumentEvent e) { refresh.restart(); }
      public void changedUpdate(DocumentEvent e) { refresh.restart(); }
    });
    direction.addActionListener(e -> rebuild());
    observedOnly.addActionListener(e -> rebuild());
    firstFrame.addChangeListener(e -> rebuild());
    lastFrame.addChangeListener(e -> rebuild());
    updateMatches();
  }
  void reset(long pid) {
    refresh.stop(); cleared.clear(); catalogCleared = false; this.pid = pid; catalog = new JsonObject(); members.clear(); pending.clear(); events.clear(); expansion.clear(); knownPaths.clear(); selected = null;
    status.setText(pid == 0 ? "Select a process and start Frida in Settings" : "PID " + pid + " / waiting for Frida catalog...");
    rebuild();
  }
  void clear() {
    refresh.stop(); cleared.addAll(events.keySet());
    events.clear(); catalog = new JsonObject(); members.clear(); pending.clear();
    expansion.clear(); knownPaths.clear(); selected = null; catalogCleared = true;
    status.setText("Cleared / waiting for new I/O events. Refresh catalog to restore loaded libraries/classes.");
    rebuild();
  }
  void accept(JsonObject value) {
    String type = DebuggerView.str(value, "type");
    if (type.equals("catalog")) {
      if (catalogCleared) return;
      catalog = value.deepCopy();
      members.clear(); pending.clear();
      status.setText("PID " + pid + " / loaded libraries and Java classes"
          + (value.has("truncated") && value.get("truncated").getAsBoolean() ? " / catalog limit reached" : "")
          + " / " + DebuggerView.str(value, "javaError"));
    } else if (type.equals("members")) {
      String key = DebuggerView.str(value, "kind") + "\n" + DebuggerView.str(value, "name");
      if (catalogCleared && !pending.contains(key)) return;
      pending.remove(key);
      List<String> names = new ArrayList<>();
      for (JsonElement member : value.getAsJsonArray("members")) names.add(member.getAsString());
      members.put(key, names);
      status.setText("PID " + pid + " / " + names.size() + " members loaded"
          + (value.has("truncated") && value.get("truncated").getAsBoolean() ? " (limited)" : ""));
    } else if (type.equals("catalogError")) {
      pending.remove(DebuggerView.str(value, "kind") + "\n" + DebuggerView.str(value, "name"));
      status.setText("Catalog: " + DebuggerView.str(value, "error"));
    }
    rebuild();
  }
  void setEvents(List<JsonObject> values) {
    events.clear();
    Set<String> retained = new HashSet<>();
    for (JsonObject event : values) {
      String id = DebuggerView.str(event, "eventId"); retained.add(id);
      if (!cleared.contains(id)) events.put(id, event);
    }
    cleared.retainAll(retained);
    if (!refresh.isRunning()) refresh.start();
  }
  Entry entry(String kind, String owner, String method) {
    Entry value = new Entry(kind, owner, method);
    return index.computeIfAbsent(value.key(), ignored -> value);
  }
  static String nativeOwner(JsonObject frame) {
    String module = DebuggerView.str(frame, "module");
    if (!module.isEmpty()) return module;
    String symbol = DebuggerView.str(frame, "symbol").replaceFirst("(?i)^0x[0-9a-f]+\\s*", "");
    int bang = symbol.indexOf('!');
    return bang >= 0 ? symbol.substring(0, bang) : "[unknown module]";
  }
  static String nativeName(JsonObject frame) {
    String name = DebuggerView.str(frame, "symbolName");
    if (!name.isEmpty()) return stripOffset(name);
    String symbol = DebuggerView.str(frame, "symbol");
    int bang = symbol.indexOf('!');
    return bang >= 0 ? stripOffset(symbol.substring(bang + 1)) : DebuggerView.str(frame, "address");
  }
  static String stripOffset(String name) { return name.replaceFirst("(?i)\\s*\\+0x[0-9a-f]+$", ""); }
  void observe(String kind, String owner, String method, JsonObject frame, String id) {
    Entry parent = entry(kind, owner, ""), child = entry(kind, owner, method);
    parent.events.add(id); child.events.add(id);
    if (kind.equals("module")) {
      Entry point = new Entry(kind, owner, method, nativeOffset(frame));
      point = index.computeIfAbsent(point.key(), ignored -> new Entry(kind, owner, method, nativeOffset(frame)));
      point.events.add(id); point.frame = frame;
    }
    if (parent.frame == null || !DebuggerView.str(frame, "origin").isEmpty()) parent.frame = frame;
    if (child.frame == null || !DebuggerView.str(frame, "origin").isEmpty()) child.frame = frame;
  }
  void rebuild() {
    String selection = selected == null ? "" : selected.key();
    index.clear();
    if (catalog.has("modules")) for (JsonElement module : catalog.getAsJsonArray("modules")) entry("module", DebuggerView.str(module.getAsJsonObject(), "path"), "");
    if (catalog.has("classes")) for (JsonElement klass : catalog.getAsJsonArray("classes")) entry("class", klass.getAsString(), "");
    for (var list : members.entrySet()) {
      String[] key = list.getKey().split("\n", 2);
      for (String name : list.getValue()) entry(key[0], key[1], key[0].equals("class") ? name.replaceFirst("\\(.*$", "") : name);
    }
    for (var item : events.entrySet()) {
      JsonObject event = item.getValue();
      if (!includesOperation(event)) continue;
      int depth = 0;
      if (event.has("nativeFrames")) for (JsonElement element : event.getAsJsonArray("nativeFrames")) {
        if (!includesFrame(depth++)) continue;
        JsonObject frame = element.getAsJsonObject();
        observe("module", nativeOwner(frame), nativeName(frame), frame, item.getKey());
      }
      depth = 0;
      if (event.has("java") && event.getAsJsonObject("java").has("frames")) for (JsonElement element : event.getAsJsonObject("java").getAsJsonArray("frames")) {
        if (!includesFrame(depth++)) continue;
        JsonObject frame = element.getAsJsonObject();
        observe("class", DebuggerView.str(frame, "className"), DebuggerView.str(frame, "methodName"), frame, item.getKey());
      }
    }
    rebuilding = true;
    try { buildTree(libraries, "module", "Libraries"); buildTree(javaTree, "class", "Java Sources"); }
    finally { rebuilding = false; }
    libraryTable.reload(); javaSourceTable.reload();
    boolean visible = false;
    for (JTree tree : new JTree[] {libraries, javaTree}) {
      Object node = tree.getLastSelectedPathComponent();
      if (node instanceof DefaultMutableTreeNode n && n.getUserObject() instanceof Entry entry && entry.key().equals(selection)) visible = true;
    }
    selected = visible ? index.get(selection) : null;
    updateMatches();
  }
  void buildTree(JTree tree, String kind, String title) {
    Set<String> expanded = expansion.computeIfAbsent(tree, ignored -> new HashSet<>());
    if (tree.getModel().getChildCount(tree.getModel().getRoot()) == 0) expanded.add("/" + title);
    String selectedKey = tree.getSelectionPath() == null ? "" : pathKey(tree.getSelectionPath());
    DefaultMutableTreeNode root = new DefaultMutableTreeNode(title);
    Map<String, DefaultMutableTreeNode> owners = new TreeMap<>(), packages = new HashMap<>(), functions = new HashMap<>();
    String filter = search.getText().trim().toLowerCase(Locale.ROOT);
    List<Entry> ordered = new ArrayList<>(index.values());
    ordered.sort((a, b) -> {
      int order = (a.kind + "\n" + a.owner + "\n" + a.method).compareTo(b.kind + "\n" + b.owner + "\n" + b.method);
      if (order != 0) return order;
      if (a.offset.startsWith("+0x") && b.offset.startsWith("+0x"))
        return new java.math.BigInteger(a.offset.substring(3), 16).compareTo(new java.math.BigInteger(b.offset.substring(3), 16));
      return a.offset.compareTo(b.offset);
    });
    for (Entry entry : ordered) {
      if (!entry.kind.equals(kind) || (observedOnly.isSelected() && entry.events.isEmpty())) continue;
      if (!(entry.owner + " " + entry.method + " " + entry.offset).toLowerCase(Locale.ROOT).contains(filter)) continue;
      DefaultMutableTreeNode parent = owners.get(entry.owner);
      if (parent == null) {
        DefaultMutableTreeNode group = root;
        if (kind.equals("class") && entry.owner.contains(".")) {
          String[] parts = entry.owner.substring(0, entry.owner.lastIndexOf('.')).split("\\.");
          String key = "";
          for (String part : parts) {
            key += "." + part;
            DefaultMutableTreeNode node = packages.get(key);
            if (node == null) { node = new DefaultMutableTreeNode(part); packages.put(key, node); group.add(node); }
            group = node;
          }
        }
        parent = new DefaultMutableTreeNode(entry(kind, entry.owner, ""));
        owners.put(entry.owner, parent); group.add(parent);
      }
      if (!entry.method.isEmpty()) {
        String functionKey = new Entry(kind, entry.owner, entry.method).key();
        DefaultMutableTreeNode function = functions.get(functionKey);
        if (function == null) {
          function = new DefaultMutableTreeNode(entry(kind, entry.owner, entry.method));
          functions.put(functionKey, function); parent.add(function);
        }
        if (!entry.offset.isEmpty()) function.add(new DefaultMutableTreeNode(entry));
      }
    }
    for (var item : owners.entrySet()) if (!observedOnly.isSelected() && item.getValue().getChildCount() == 0 && !members.containsKey(kind + "\n" + item.getKey()))
      item.getValue().add(new DefaultMutableTreeNode("Expand to load " + (kind.equals("module") ? "exported functions" : "methods")));
    Set<String> known = knownPaths.computeIfAbsent(tree, ignored -> new HashSet<>());
    HierarchyTable hierarchy = tree == libraries ? libraryTable : javaSourceTable;
    Enumeration<?> defaults = root.depthFirstEnumeration();
    while (defaults.hasMoreElements()) {
      DefaultMutableTreeNode node = (DefaultMutableTreeNode) defaults.nextElement();
      String key = pathKey(new TreePath(node.getPath()));
      if (!node.isLeaf() && known.add(key) && (node.isRoot() || hierarchy.autoExpand.getSelectedIndex() == 0)) expanded.add(key);
    }
    tree.setModel(new DefaultTreeModel(root));

    Enumeration<?> nodes = root.depthFirstEnumeration();
    while (nodes.hasMoreElements()) {
      DefaultMutableTreeNode node = (DefaultMutableTreeNode) nodes.nextElement();
      TreePath path = new TreePath(node.getPath());
      String key = pathKey(path);
      if (expanded.contains(key)) tree.expandPath(path);
    }
    // Expanding a hidden child opens its ancestors; restore each collapsed ancestor afterwards.
    nodes = root.depthFirstEnumeration();
    while (nodes.hasMoreElements()) {
      DefaultMutableTreeNode node = (DefaultMutableTreeNode) nodes.nextElement();
      TreePath path = new TreePath(node.getPath());
      if (!expanded.contains(pathKey(path))) tree.collapsePath(path);
      if (selectedKey.equals(pathKey(path))) tree.setSelectionPath(path);
    }
  }
  JPanel hierarchyPanel(HierarchyTable table) {
    JPanel panel = new JPanel(new BorderLayout());
    JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 3));
    controls.add(new JLabel("Automatic:")); controls.add(table.autoExpand);
    controls.add(new JLabel("Click arrow to expand; right-click for more"));
    panel.add(UiLayout.horizontal(controls), BorderLayout.NORTH);
    panel.add(hierarchyScroll(table));
    return panel;
  }
  static void styleTable(JTable table) {
    table.setRowHeight(27);
    table.setShowVerticalLines(false);
    table.setShowHorizontalLines(false);
    table.setIntercellSpacing(new Dimension(0, 0));
    table.setFillsViewportHeight(true);
  }
  static JScrollPane hierarchyScroll(JTable table) {
    JScrollPane pane = new JScrollPane(table);
    pane.setColumnHeaderView(table.getTableHeader());
    return pane;
  }
  static String nativeOffset(JsonObject frame) {
    String offset = DebuggerView.str(frame, "functionOffset");
    if (offset.matches("(?i)0x[0-9a-f]+")) return "+0x" + new java.math.BigInteger(offset.substring(2), 16).toString(16);
    java.util.regex.Matcher match = java.util.regex.Pattern.compile("\\+(0x[0-9a-fA-F]+)$").matcher(DebuggerView.str(frame, "symbolName"));
    if (!match.find()) match = java.util.regex.Pattern.compile("\\+(0x[0-9a-fA-F]+)$").matcher(DebuggerView.str(frame, "symbol"));
    else return "+0x" + new java.math.BigInteger(match.group(1).substring(2), 16).toString(16);
    if (match.find()) return "+0x" + new java.math.BigInteger(match.group(1).substring(2), 16).toString(16);
    String address = DebuggerView.str(frame, "address");
    return address.isEmpty() ? "Offset unavailable" : "PC " + address + " (offset unavailable)";
  }
  static String nodeType(DefaultMutableTreeNode node, boolean javaTree) {
    if (node.getUserObject() instanceof Entry entry) {
      if (!entry.offset.isEmpty()) return "Offset";
      if (!entry.method.isEmpty()) return entry.kind.equals("class") ? "Method" : "Function";
      return entry.kind.equals("class") ? "Class" : "Module";
    }
    if (node.isRoot()) return "Catalog";
    return javaTree && !node.isLeaf() ? "Package" : "Info";
  }
  /** Vector icons stay crisp at display scaling and inherit the selected row's contrast. */
  static final class NodeIcon implements Icon {
    final String type;
    final boolean branch, expanded;
    NodeIcon(String type, boolean branch, boolean expanded) { this.type = type; this.branch = branch; this.expanded = expanded; }
    public int getIconWidth() { return 36; }
    public int getIconHeight() { return 18; }
    public void paintIcon(Component c, Graphics graphics, int x, int y) {
      Graphics2D g = (Graphics2D) graphics.create();
      g.translate(x, y); g.setColor(c.getForeground());
      g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
      g.setStroke(new BasicStroke(1.7f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
      if (branch) {
        if (expanded) g.drawPolyline(new int[] {4, 8, 12}, new int[] {6, 10, 6}, 3);
        else g.drawPolyline(new int[] {6, 10, 6}, new int[] {4, 8, 12}, 3);
      }
      g.translate(18, 0);
      switch (type) {
        case "Package":
          java.awt.geom.Path2D folder = new java.awt.geom.Path2D.Float();
          folder.moveTo(1, 5); folder.quadTo(1, 3, 3, 3); folder.lineTo(6, 3);
          folder.lineTo(8, 5); folder.lineTo(14, 5); folder.quadTo(16, 5, 16, 7);
          folder.lineTo(16, 13); folder.quadTo(16, 15, 14, 15); folder.lineTo(3, 15);
          folder.quadTo(1, 15, 1, 13); folder.closePath(); g.fill(folder); break;
        case "Class":
          g.drawRoundRect(2, 2, 13, 14, 3, 3);
          g.drawLine(2, 7, 15, 7); g.drawLine(6, 10, 11, 10); g.drawLine(6, 13, 10, 13); break;
        case "Module":
        case "Catalog":
          for (int row = 0; row < 2; row++) for (int col = 0; col < 2; col++)
            g.fillRoundRect(2 + col * 8, 2 + row * 8, 6, 6, 2, 2);
          break;
        case "Function":
          g.drawPolyline(new int[] {5, 1, 5}, new int[] {4, 9, 14}, 3);
          g.drawPolyline(new int[] {12, 16, 12}, new int[] {4, 9, 14}, 3);
          g.drawLine(10, 3, 7, 15); break;
        case "Method":
          g.drawLine(2, 4, 2, 10); g.drawLine(2, 10, 14, 10);
          g.drawPolyline(new int[] {10, 14, 10}, new int[] {6, 10, 14}, 3); break;
        case "Offset":
          g.fillOval(2, 7, 4, 4); g.drawLine(9, 9, 16, 9); break;
        default:
          g.drawOval(2, 2, 14, 14); g.drawLine(9, 8, 9, 12); g.fillOval(8, 5, 2, 2);
      }
      g.dispose();
    }
  }
  /** A table of visible tree paths; the backing tree owns expansion and selection state. */
  final class HierarchyTable extends JTable {
    final JTree tree;
    final JComboBox<String> autoExpand = new JComboBox<>(new String[] {"Expand", "Collapse"});
    final JPopupMenu menu = new JPopupMenu();
    boolean syncing;
    HierarchyTable(JTree tree) {
      this.tree = tree;
      autoExpand.setSelectedIndex(1);
      autoExpand.setToolTipText("Default for new items. Changing this reapplies the setting to the whole hierarchy; right-click overrides individual branches.");
      autoExpand.addActionListener(e -> {
        tree.clearSelection(); selected = null;
        expansion.remove(tree); knownPaths.remove(tree); rebuild();
      });
      for (String action : new String[] {"Expand", "Collapse", "Expand subtree", "Collapse subtree"}) {
        JMenuItem item = new JMenuItem(action);
        item.addActionListener(e -> {
          TreePath path = tree.getSelectionPath(); if (path == null) return;
          if (action.endsWith("subtree")) branch(action.startsWith("Expand"));
          else if (action.equals("Expand")) tree.expandPath(path);
          else tree.collapsePath(path);
        });
        menu.add(item);
      }
      setModel(new javax.swing.table.AbstractTableModel() {
        public int getRowCount() { return tree.getRowCount(); }
        public int getColumnCount() { return 1; }
        public String getColumnName(int col) { return "Name"; }
        public Class<?> getColumnClass(int col) { return Object.class; }
        public Object getValueAt(int row, int col) {
          DefaultMutableTreeNode node = (DefaultMutableTreeNode) tree.getPathForRow(row).getLastPathComponent();
          return node.getUserObject();
        }
      });
      styleTable(this); setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
      setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
      getColumnModel().getColumn(0).setPreferredWidth(360);

      getTableHeader().setReorderingAllowed(false);
      getTableHeader().setToolTipText("Right-click an item to expand or collapse it or its subtree");
      getColumnModel().getColumn(0).setCellRenderer(new javax.swing.table.DefaultTableCellRenderer() {
        public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focus, int row, int col) {
          super.getTableCellRendererComponent(table, value, selected, focus, row, col);
          TreePath path = tree.getPathForRow(row);
          DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
          Color bg = table.getBackground();
          boolean dark = bg.getRed() + bg.getGreen() + bg.getBlue() < 384;
          setBackground(selected ? table.getSelectionBackground() : bg);
          Color color = value instanceof Entry entry
              ? !entry.offset.isEmpty() ? (dark ? new Color(230, 183, 115) : new Color(146, 88, 26))
              : entry.method.isEmpty() ? (dark ? new Color(158, 180, 242) : new Color(61, 82, 143))
              : (dark ? new Color(115, 207, 177) : new Color(29, 118, 91))
              : nodeType(node, tree == javaTree).equals("Package") ? (dark ? new Color(221, 185, 115) : new Color(150, 107, 40))
              : table.getForeground();
          setForeground(selected ? table.getSelectionForeground() : color);
          setFont(table.getFont().deriveFont(value instanceof Entry entry && entry.method.isEmpty() ? Font.BOLD : Font.PLAIN));
          setBorder(BorderFactory.createEmptyBorder(0, 5 + (path.getPathCount() - 1) * 18, 0, 4));
          String type = nodeType(node, tree == javaTree);
          setIcon(new NodeIcon(type, !node.isLeaf(), tree.isExpanded(path)));
          setIconTextGap(5);
          setText(value.toString());
          setToolTipText(type + ": " + (value instanceof Entry entry ? entry.owner + (entry.method.isEmpty() ? "" : "!" + entry.method) + entry.offset : value.toString()));
          getAccessibleContext().setAccessibleDescription(type + ": " + value);
          return this;
        }
      });
      getSelectionModel().addListSelectionListener(e -> {
        if (!syncing && !e.getValueIsAdjusting()) tree.setSelectionRow(getSelectedRow());
      });
      tree.addTreeSelectionListener(e -> syncSelection());
      tree.addTreeExpansionListener(new TreeExpansionListener() {
        public void treeExpanded(TreeExpansionEvent e) { if (!rebuilding) expansion.computeIfAbsent(tree, ignored -> new HashSet<>()).add(pathKey(e.getPath())); if (!rebuilding) reload(); }
        public void treeCollapsed(TreeExpansionEvent e) { if (!rebuilding) expansion.computeIfAbsent(tree, ignored -> new HashSet<>()).remove(pathKey(e.getPath())); if (!rebuilding) reload(); }
      });
      addMouseListener(new MouseAdapter() {
        public void mouseClicked(MouseEvent e) {
          if (!SwingUtilities.isLeftMouseButton(e)) return;
          int row = rowAtPoint(e.getPoint());
          if (row < 0 || columnAtPoint(e.getPoint()) != 0) return;
          TreePath path = tree.getPathForRow(row);
          int handle = 5 + (path.getPathCount() - 1) * 18;
          boolean disclosure = e.getX() >= handle && e.getX() < handle + 18;
          if ((disclosure && e.getClickCount() == 1) || (!disclosure && e.getClickCount() == 2)) toggle(path);
        }
        public void mousePressed(MouseEvent e) { popup(e); }
        public void mouseReleased(MouseEvent e) { popup(e); }
        void popup(MouseEvent e) {
          if (!e.isPopupTrigger()) return;
          int row = rowAtPoint(e.getPoint());
          if (row < 0) return;
          setRowSelectionInterval(row, row);
          boolean branch = !((DefaultMutableTreeNode) tree.getPathForRow(row).getLastPathComponent()).isLeaf();
          for (Component item : menu.getComponents()) item.setEnabled(branch);
          menu.show(HierarchyTable.this, e.getX(), e.getY());
        }
      });
      getInputMap().put(KeyStroke.getKeyStroke("shift F10"), "popup");
      getActionMap().put("popup", new AbstractAction() {
        public void actionPerformed(ActionEvent e) {
          int row = getSelectedRow(); if (row < 0) return;
          boolean branch = !((DefaultMutableTreeNode) tree.getPathForRow(row).getLastPathComponent()).isLeaf();
          for (Component item : menu.getComponents()) item.setEnabled(branch);
          Rectangle cell = getCellRect(row, 0, true); menu.show(HierarchyTable.this, cell.x + 20, cell.y + cell.height);
        }
      });
      for (String key : new String[] {"LEFT", "RIGHT"}) {
        getInputMap().put(KeyStroke.getKeyStroke(key), key);
        getActionMap().put(key, new AbstractAction() {
          public void actionPerformed(ActionEvent e) {
            TreePath path = tree.getSelectionPath(); if (path == null) return;
            if (key.equals("RIGHT")) tree.expandPath(path);
            else if (tree.isExpanded(path)) tree.collapsePath(path);
            else tree.setSelectionPath(path.getParentPath());
          }
        });
      }
    }
    void branch(boolean expand) {
      TreePath path = tree.getSelectionPath();
      if (path == null) path = new TreePath(((DefaultMutableTreeNode) tree.getModel().getRoot()).getPath());
      DefaultMutableTreeNode root = (DefaultMutableTreeNode) path.getLastPathComponent();
      Set<String> state = expansion.computeIfAbsent(tree, ignored -> new HashSet<>());
      if (expand) for (TreePath parent = path.getParentPath(); parent != null; parent = parent.getParentPath()) state.add(pathKey(parent));
      // Bulk expansion only exposes existing nodes; it never fetches every class's members.
      rebuilding = true;
      try {
        Enumeration<?> nodes = root.depthFirstEnumeration();
        while (nodes.hasMoreElements()) {
          DefaultMutableTreeNode node = (DefaultMutableTreeNode) nodes.nextElement();
          TreePath child = new TreePath(node.getPath());
          if (expand) { if (!node.isLeaf()) state.add(pathKey(child)); tree.expandPath(child); }
          else { state.remove(pathKey(child)); tree.collapsePath(child); }
        }
      } finally { rebuilding = false; }
      tree.setSelectionPath(path); reload();
    }
    void toggle(TreePath path) { if (tree.isExpanded(path)) tree.collapsePath(path); else tree.expandPath(path); }
    void syncSelection() {
      syncing = true;
      try { int row = tree.getSelectionPath() == null ? -1 : tree.getRowForPath(tree.getSelectionPath()); if (row < 0) clearSelection(); else setRowSelectionInterval(row, row); }
      finally { syncing = false; }
    }
    void reload() {
      syncing = true;
      try { ((javax.swing.table.AbstractTableModel) getModel()).fireTableDataChanged(); }
      finally { syncing = false; }
      syncSelection();
    }
  }
  static String pathKey(TreePath path) {
    StringBuilder key = new StringBuilder();
    for (Object part : path.getPath()) {
      Object value = ((DefaultMutableTreeNode) part).getUserObject();
      key.append('/').append(value instanceof Entry entry ? entry.key() : value);
    }
    return key.toString();
  }
  boolean includesOperation(JsonObject event) {
    String operation = DebuggerView.str(event, "operation");
    return direction.getSelectedIndex() == 0 || operation.equals(direction.getSelectedIndex() == 1 ? "send" : "receive");
  }
  boolean includesFrame(int frame) {
    int start = (Integer) firstFrame.getValue(), count = (Integer) lastFrame.getValue();
    return frame >= start && (count == 0 || frame - start < count);
  }
  void requestMembers(Entry entry) {
    String key = entry.kind + "\n" + entry.owner;
    if (members.containsKey(key) || !pending.add(key)) return;
    JsonObject command = new JsonObject(); command.addProperty("action", "members");
    command.addProperty("kind", entry.kind); command.addProperty("name", entry.owner);
    request.accept(command);
  }
  void updateMatches() {
    matches.setRowCount(0); matchingIds.clear();
    load.setEnabled(selected != null); source.setEnabled(selected != null && selected.kind.equals("class"));
    openEvent.setEnabled(false);
    if (selected == null) return;
    for (String id : selected.events) {
      JsonObject event = events.get(id);
      if (event == null) continue;
      matchingIds.add(id);
      String time = event.has("capturedAtEpochMs") ? java.time.Instant.ofEpochMilli(event.get("capturedAtEpochMs").getAsLong()).atZone(java.time.ZoneId.systemDefault()).toLocalTime().toString() : "";
      matches.addRow(new Object[] {time, DebuggerView.str(event, "tid"), DebuggerView.str(event, "operation"), matchingFrames(event), DebuggerView.str(event, "syscallPc"), ioResult(event)});
    }
  }
  String matchingFrames(JsonObject event) {
    boolean nativeStack = selected.kind.equals("module");
    JsonArray frames = nativeStack ? event.getAsJsonArray("nativeFrames")
        : event.has("java") ? event.getAsJsonObject("java").getAsJsonArray("frames") : null;
    if (frames == null) return "";
    List<String> indices = new ArrayList<>();
    for (int i = 0; i < frames.size(); i++) {
      if (!includesFrame(i)) continue;
      JsonObject frame = frames.get(i).getAsJsonObject();
      String owner = nativeStack ? nativeOwner(frame) : DebuggerView.str(frame, "className");
      String method = nativeStack ? nativeName(frame) : DebuggerView.str(frame, "methodName");
      if (selected.owner.equals(owner) && (selected.method.isEmpty() || selected.method.equals(method))
          && (selected.offset.isEmpty() || selected.offset.equals(nativeOffset(frame)))) indices.add("#" + i);
    }
    return (nativeStack ? "Native " : "Java ") + String.join(", ", indices);
  }
  static String ioResult(JsonObject event) {
    String value = DebuggerView.str(event, "result");
    if (value.isEmpty()) return "Not captured";
    try {
      long result = Long.parseLong(value);
      if (result < 0) return "Error (errno " + -result + ")";
      String unit = DebuggerView.str(event, "resultUnit");
      return value + (unit.isEmpty() ? " (return value)" : " " + unit);
    } catch (NumberFormatException ignored) { return value; }
  }
  void openSelected() {
    int row = table.getSelectedRow();
    if (row >= 0) navigate.accept(matchingIds.get(table.convertRowIndexToModel(row)));
  }
}
