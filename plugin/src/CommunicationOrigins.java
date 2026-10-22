package ebpfproxy;

import com.google.gson.*;
import packetproxy.model.Extension;
import packetproxy.gui.TableHeaderStyle;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import java.awt.*;
import java.nio.file.*;
import java.io.*;
import java.time.*;
import java.util.*;
import java.util.List;
import java.util.regex.Pattern;

/** Passive observations only: never inserts History records or sends network traffic. */
public final class CommunicationOrigins extends Extension {
  private JPanel panel;
  private Path file;
  private JLabel status;
  private JLabel packetScope;
  private JTextField path;
  private JTable connections, packets;
  private DefaultTableModel connectionRows, packetRows;
  private JTextArea details, bytes;
  private DebuggerView connectView;
  private JTable ioEvents;
  private DefaultTableModel eventRows;
  private DebuggerView eventView;
  private JLabel eventScope;
  private JTabbedPane tabs;
  private JComponent eventPanel;
  private ProcessBrowser processBrowser;
  private final JComboBox<String> eventMode =
      new JComboBox<>(new String[] {"None", "Manual", "Frida"});
  private final List<JsonObject> capturedEvents = new ArrayList<>();
  private FridaStream stream;
  private long streamPid;
  private String streamStatus = "";
  private void updateStream() {
    long pid = 0;
    JsonObject target = null;
    for (JsonElement entry : flows) {
      JsonObject flow = entry.getAsJsonObject();
      if (Objects.equals(selected, str(flow, "connectionId"))) {
        pid = number(flow, "pid");
        target = origins.get(selected);
        if (target == null) {
          target = new JsonObject();
          target.addProperty("pid", pid);
          target.addProperty("connectionId", selected);
          target.addProperty("capturedAtBootNs", selected.substring(selected.lastIndexOf('/') + 1));
        }
        break;
      }
    }
    if (eventMode.getSelectedIndex() != 2) {
      if (stream != null)
        stream.stop();
      stream = null;
      streamPid = 0;
      return;
    }
    if (pid == 0 || pid == streamPid)
      return;
    if (stream != null)
      stream.stop();
    streamPid = pid;
    capturedEvents.clear();
    if (processBrowser != null) processBrowser.reset(pid);
    streamStatus = "Attaching to PID " + pid + "...";
    FridaStream active = new FridaStream();
    stream = active;
    active.start(target.deepCopy(), event -> {
      if (stream != active)
        return;
      String type = str(event, "type");
      if (type.equals("event")) {
        capturedEvents.removeIf(old -> str(old, "eventId").equals(str(event, "eventId")));
        capturedEvents.add(event);
        while (capturedEvents.size() > 1000) capturedEvents.remove(0);
        syncBrowserEvents();
      } else if (type.equals("ready"))
        streamStatus = "Collecting PID " + streamPid + " / all TIDs";
      else if (type.equals("error"))
        streamStatus = "Stopped: " + str(event, "error");
      else if (type.equals("stats"))
        streamStatus =
            "Collecting PID " + streamPid + " / all TIDs / dropped " + str(event, "dropped");
      else if (Set.of("catalog", "members", "catalogError").contains(type)) {
        processBrowser.accept(event);
        return;
      }
      renderEvents();
    });
  }
  private JsonArray events = new JsonArray();
  private final List<JsonObject> visibleEvents = new ArrayList<>();
  private String selectedEvent, renderedEvent;
  private boolean updatingEvents;
  private final Map<String, JsonObject> origins = new HashMap<>();
  private String renderedOrigin;
  private JsonArray flows = new JsonArray(), copies = new JsonArray();
  private final List<JsonObject> visibleCopies = new ArrayList<>();
  private javax.swing.Timer timer;
  private boolean busy, updating;
  private String selected;
  private long generation;
  private final Map<String, Long> synTimes = new HashMap<>();
  private final Set<String> clearedConnections = new HashSet<>(), clearedPackets = new HashSet<>(),
                            clearedEvents = new HashSet<>();
  private JsonObject lastRoot;
  private static void clearMenu(JTable table, Runnable action) {
    JPopupMenu menu = new JPopupMenu();
    JMenuItem clear = new JMenuItem("Clear");
    clear.addActionListener(e -> action.run());
    menu.add(clear);
    table.setComponentPopupMenu(menu);
  }
  private void clearConnections() {
    for (JsonElement e : flows) clearedConnections.add(str(e.getAsJsonObject(), "connectionId"));
    selected = null;
    if (lastRoot != null)
      render(lastRoot);
  }
  private void clearPackets() {
    for (JsonObject p : visibleCopies) clearedPackets.add(p.toString());
    renderDetails();
  }
  private void clearEvents() {
    for (JsonObject e : visibleEvents) clearedEvents.add(str(e, "eventId"));
    selectedEvent = null;
    renderedEvent = null;
    syncBrowserEvents();
    renderEvents();
  }
  private void syncBrowserEvents() {
    if (processBrowser != null)
      processBrowser.setEvents(capturedEvents.stream().filter(event -> !clearedEvents.contains(str(event, "eventId"))).toList());
  }
  private void requestInspection(JsonObject command) {
    try {
      if (stream == null) throw new IOException("Select Frida in Settings and a connection first");
      stream.request(command);
    } catch (IOException ex) {
      JsonObject error = command.deepCopy();
      error.addProperty("type", "catalogError"); error.addProperty("error", ex.getMessage());
      processBrowser.accept(error);
    }
  }
  private void openCapturedEvent(String id) {
    selectedEvent = id;
    renderEvents();
    tabs.setSelectedComponent(eventPanel);
  }
  private void updateBrowserTab() {
    if (tabs == null || processBrowser == null) return;
    if (eventMode.getSelectedIndex() == 2) {
      if (tabs.indexOfComponent(processBrowser) < 0) tabs.addTab("Modules / Java", processBrowser);
    } else {
      tabs.remove(processBrowser);
      processBrowser.reset(0);
    }
  }

  public CommunicationOrigins() {
    setName("eBPF Analyzer");
    setEnabled(true);
  }
  public CommunicationOrigins(String name, String path) {
    this();
    setName(name);
    setPath(path);
  }

  @Override
  public JComponent createPanel() {
    // Old database registrations remain inert after renaming the extension.
    if ("\u901a\u4fe1\u7b87\u6240".equals(getName()))
      return null;
    if (panel != null)
      return panel; // Host may call createPanel twice.
    panel = new JPanel(new BorderLayout());
    panel.putClientProperty("ebpf.eventMode", eventMode);
    Path defaultFile =
        Path.of("../ebpf-analyzer/captures/monitor.json").toAbsolutePath().normalize();
    file = Path.of(System.getProperty("packetproxy.monitor.file", defaultFile.toString()));
    JPanel top = new JPanel(new BorderLayout(4, 4));
    path = new JTextField(file.toString());
    path.setEditable(false);
    JButton open = UiLayout.button("Open Monitor File...");
    open.addActionListener(e -> {
      JFileChooser chooser = new JFileChooser(file.toFile());
      chooser.setLocale(Locale.ENGLISH);
      chooser.updateUI();
      chooser.setDialogTitle("Open Monitor File");
      if (chooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
        file = chooser.getSelectedFile().toPath();
        path.setText(file.toString());
        generation++;
        synTimes.clear();
        clearedConnections.clear();
        clearedPackets.clear();
        clearedEvents.clear();
        if (stream != null)
          stream.stop();
        stream = null;
        streamPid = 0;
        if (processBrowser != null) processBrowser.reset(0);
        clear();
        refresh();
      }
    });
    open.setToolTipText("Select captures/monitor.json created by the host monitor");
    status = new JLabel("Start the host monitor, then open captures/monitor.json.");
    JPanel fileRow = new JPanel(new BorderLayout(4, 0));
    fileRow.add(new JLabel("Monitor file:"), BorderLayout.WEST);
    fileRow.add(path, BorderLayout.CENTER);
    top.add(fileRow, BorderLayout.NORTH);
    top.add(status, BorderLayout.CENTER);
    JPanel fileButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
    fileButtons.add(open);
    JButton settings = UiLayout.button("Settings");
    settings.addActionListener(e -> AnalyzerSettings.show(panel, eventMode));
    fileButtons.add(settings);
    top.add(UiLayout.horizontal(fileButtons), BorderLayout.SOUTH);
    panel.add(top, BorderLayout.SOUTH);
    JLabel guide = new JLabel("<html>Start the host monitor, then click <b>Open Monitor File...</b> "
        + "at the bottom right to select <b>captures/monitor.json</b>.<br>"
        + "Generate a new TCP connection in the app, then select its row below to inspect packets and stacks.</html>");
    guide.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
    panel.add(guide, BorderLayout.NORTH);
    connectionRows = rows(
        "SYN Time", "PID", "UID", "App", "Process", "Client", "Server", "Status", "PC", "Updated");
    connections = new JTable(connectionRows);
    connections.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    styleTable(connections);
    clearMenu(connections, this::clearConnections);
    connections.setToolTipText("SYN Time: connection start. Updated: latest observation of the "
                               + "connection, not the last payload transfer.");
    // Keep technical fields available in Details, rather than crowding the list.
    for (int column : new int[] {8, 4, 2})
      connections.removeColumn(connections.getColumnModel().getColumn(column));
    TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(connectionRows);
    connections.setRowSorter(sorter);
    JTextField filter = new JTextField() {
      @Override
      protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        if (getText().isEmpty()) {
          Graphics copy = g.create();
          copy.setColor(UIManager.getColor("TextField.inactiveForeground"));
          Insets in = getInsets();
          copy.drawString("Filter by app, PID or address", in.left + 2,
              (getHeight() - getFontMetrics(getFont()).getHeight()) / 2
                  + getFontMetrics(getFont()).getAscent());
          copy.dispose();
        }
      }
    };
    filter.getDocument().addDocumentListener(new DocumentListener() {
      private void update() {
        sorter.setRowFilter(filter.getText().isEmpty()
                ? null
                : RowFilter.regexFilter("(?i)" + Pattern.quote(filter.getText())));
      }
      public void insertUpdate(DocumentEvent e) {
        update();
      }
      public void removeUpdate(DocumentEvent e) {
        update();
      }
      public void changedUpdate(DocumentEvent e) {
        update();
      }
    });
    JPanel list = new JPanel(new BorderLayout());
    JPanel search = new JPanel(new BorderLayout(6, 0));
    search.add(new JLabel("Filter: "), BorderLayout.WEST);
    search.add(filter);
    filter.setToolTipText("Filter by app, PID or address");
    list.add(search, BorderLayout.NORTH);
    list.add(new JScrollPane(connections));
    details = textArea();
    bytes = textArea();
    connectView = new DebuggerView();
    packetRows = rows("Time", "Type", "Source", "Destination", "Length", "Direction");
    packets = new JTable(packetRows);
    packets.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    styleTable(packets);
    clearMenu(packets, this::clearPackets);
    packets.getColumnModel().getColumn(5).setPreferredWidth(65);
    packets.setToolTipText("\u2192 Client request   /   \u2190 Server response");
    packets.getSelectionModel().addListSelectionListener(e -> {
      if (e.getValueIsAdjusting())
        return;
      int row = packets.getSelectedRow();
      bytes.setText(row < 0 || row >= visibleCopies.size() ? "" : hex(visibleCopies.get(row)));
      bytes.setCaretPosition(0);
    });
    JSplitPane packetSplit =
        new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(packets), new JScrollPane(bytes));
    packetSplit.setResizeWeight(.5);
    JPanel packetPanel = new JPanel(new BorderLayout());
    packetScope = new JLabel("Select a connection");
    JPanel packetToolbar = new JPanel(new BorderLayout());
    packetToolbar.add(packetScope);
    packetPanel.add(packetToolbar, BorderLayout.NORTH);
    packetPanel.add(packetSplit);
    tabs = new JTabbedPane();
    processBrowser = new ProcessBrowser(this::requestInspection, this::openCapturedEvent);
    tabs.addTab("Details", new JScrollPane(details));
    tabs.addTab("Packets", packetPanel);
    eventPanel = createEventsPanel();
    tabs.addTab("I/O Events", eventPanel);
    tabs.addTab("Connect", connectView);
    JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, list, tabs);
    split.setResizeWeight(.5);
    panel.add(split);
    connections.getSelectionModel().addListSelectionListener(e -> {
      if (updating || e.getValueIsAdjusting())
        return;
      int row = connections.getSelectedRow();
      selected = row < 0 ? null
                         : str(flows.get(connections.convertRowIndexToModel(row)).getAsJsonObject(),
                               "connectionId");
      renderDetails();
    });
    timer = new javax.swing.Timer(1000, e -> refresh());
    panel.addHierarchyListener(e -> {
      if (panel.isShowing()) {
        timer.start();
        refresh();
      } else {
        timer.stop();
      }
    });
    refresh();
    return panel;
  }

  private static DefaultTableModel rows(String... columns) {
    return new DefaultTableModel(columns, 0) {
      @Override
      public boolean isCellEditable(int r, int c) {
        return false;
      }
    };
  }
  static void styleTable(JTable table) {
    table.setFillsViewportHeight(true);
    table.setRowHeight(table.getFontMetrics(table.getFont()).getHeight());
    table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
      @Override
      public Component getTableCellRendererComponent(
          JTable t, Object value, boolean selected, boolean focus, int row, int column) {
        Component c = super.getTableCellRendererComponent(t, value, selected, focus, row, column);
        if (!selected)
          c.setBackground(row % 2 == 0 ? Color.WHITE : new Color(0xf0, 0xf0, 0xf0));
        return c;
      }
    });
    TableHeaderStyle.apply(table, table.getColumnCount());
  }
  private static JTextArea textArea() {
    JTextArea a = new JTextArea();
    a.setEditable(false);
    a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
    return a;
  }
  private static String str(JsonObject o, String k) {
    return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : "";
  }
  private static long number(JsonObject o, String k) {
    return o.has(k) ? o.get(k).getAsLong() : 0;
  }
  private static String time(long value) {
    return java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
        .format(Instant.ofEpochMilli(value).atZone(ZoneId.systemDefault()));
  }
  private static String endpoint(JsonObject o, String ip, String port) {
    String a = displayIP(str(o, ip));
    return (a.contains(":") ? "[" + a + "]" : a) + ":" + str(o, port);
  }

  static String displayIP(String value) {
    // Parse numeric IPv6 only; never resolve hostnames or turn native IPv6 into IPv4.
    if (!value.contains(":"))
      return value;
    try {
      java.net.InetAddress address = java.net.InetAddress.getByName(value);
      if (address instanceof java.net.Inet4Address)
        return address.getHostAddress();
    } catch (java.net.UnknownHostException ignored) {
    }
    return value;
  }
  static String displayEndpoint(String value) {
    if (!value.startsWith("["))
      return value;
    int end = value.indexOf(']');
    if (end < 0)
      return value;
    String ip = displayIP(value.substring(1, end));
    return (ip.contains(":") ? "[" + ip + "]" : ip) + value.substring(end + 1);
  }

  static JsonObject read(Path file) throws IOException {
    byte[] data;
    try (InputStream in = Files.newInputStream(file)) {
      data = in.readNBytes(16 * 1024 * 1024 + 1);
    }
    if (data.length > 16 * 1024 * 1024)
      throw new IOException("snapshot exceeds 16 MiB");
    try {
      JsonObject root =
          JsonParser.parseString(new String(data, java.nio.charset.StandardCharsets.UTF_8))
              .getAsJsonObject();
      if (number(root, "schemaVersion") != 1 || !str(root, "mode").equals("passive"))
        throw new IOException("passive schema required");
      if (root.getAsJsonArray("connections").size() > 2000
          || root.getAsJsonArray("packets").size() > 512)
        throw new IOException("snapshot count limit exceeded");
      Set<String> ids = new HashSet<>();
      for (JsonElement entry : root.getAsJsonArray("connections")) {
        JsonObject c = entry.getAsJsonObject();
        String id = str(c, "connectionId");
        if (id.isEmpty() || !ids.add(id) || number(c, "pid") <= 0
            || number(c, "validToEpochMs") <= number(c, "validFromEpochMs"))
          throw new IOException("invalid connection lifetime");
      }
      for (JsonElement entry : root.getAsJsonArray("packets")) {
        JsonObject p = entry.getAsJsonObject();
        byte[] b = Base64.getDecoder().decode(str(p, "data"));
        if (b.length > 2048 || number(p, "originalLength") < b.length)
          throw new IOException("invalid packet length");
      }
      for (String group : new String[] {"origins", "ioEvents"})
        if (root.has(group) && !root.get(group).isJsonNull()) {
          JsonArray entries = root.getAsJsonArray(group);
          if (entries.size() > 128)
            throw new IOException("origin snapshot count limit exceeded");
          Set<String> originIds = new HashSet<>();
          for (JsonElement entry : entries) {
            JsonObject o = entry.getAsJsonObject();
            String id = str(o, group.equals("ioEvents") ? "eventId" : "connectionId");
            byte[] raw = Base64.getDecoder().decode(str(o, "stack"));
            if (id.isEmpty() || !originIds.add(id) || !str(o, "architecture").equals("x86_64")
                || raw.length > 16384 || raw.length != number(o, "capturedBytes")
                || raw.length > number(o, "requestedBytes")
                || (number(o, "requestedBytes") != 4096 && number(o, "requestedBytes") != 16384))
              throw new IOException("invalid raw stack snapshot");
            if (!str(o, "stackBase").matches("0x[0-9a-fA-F]{16}"))
              throw new IOException("invalid stack address");
            if (!o.get("registers").isJsonObject() || o.getAsJsonObject("registers").size() > 21)
              throw new IOException("invalid registers");
            if (group.equals("ioEvents")
                && (!Set.of("send", "receive").contains(str(o, "operation"))
                    || !str(o, "phase").equals("entry") || number(o, "tid") <= 0))
              throw new IOException("invalid I/O event");
          }
        }
      return root;
    } catch (RuntimeException e) {
      throw new IOException("invalid monitor JSON", e);
    }
  }
  private void refresh() {
    if (busy)
      return;
    busy = true;
    Path current = file;
    long version = generation;
    new SwingWorker<JsonObject, Void>() {
      protected JsonObject doInBackground() throws Exception {
        return read(current);
      }
      protected void done() {
        busy = false;
        if (version != generation) {
          refresh();
          return;
        }
        try {
          render(get());
        } catch (Exception e) {
          clear();
          Throwable cause = e.getCause() == null ? e : e.getCause();
          status.setText(cause instanceof NoSuchFileException
                  ? "File not found. Start the monitor, then click Open Monitor File... at the bottom right."
                  : "Unable to read monitor file. Select a valid monitor.json with Open Monitor File...");
          status.setToolTipText(current + " | " + cause.getMessage());
        }
      }
    }.execute();
  }
  private void clear() {
    if (connectionRows == null)
      return;
    updating = true;
    connectionRows.setRowCount(0);
    updating = false;
    flows = new JsonArray();
    copies = new JsonArray();
    events = new JsonArray();
    origins.clear();
    selected = null;
    renderDetails();
  }
  private void render(JsonObject root) {
    lastRoot = root;
    Set<String> current = new HashSet<>();
    flows = new JsonArray();
    for (JsonElement entry : root.getAsJsonArray("connections")) {
      JsonObject c = entry.getAsJsonObject().deepCopy();
      String id = str(c, "connectionId");
      current.add(id);
      long start = synTimes.computeIfAbsent(id, k -> number(c, "validFromEpochMs"));
      c.addProperty("validFromEpochMs", start);
      if (!clearedConnections.contains(id))
        flows.add(c);
    }
    synTimes.keySet().retainAll(current);
    clearedConnections.retainAll(current);
    copies = root.getAsJsonArray("packets");
    Set<String> packetKeys = new HashSet<>();
    for (JsonElement entry : copies) packetKeys.add(entry.toString());
    clearedPackets.retainAll(packetKeys);
    events = root.has("ioEvents") && !root.get("ioEvents").isJsonNull()
        ? root.getAsJsonArray("ioEvents")
        : new JsonArray();
    Set<String> eventKeys = new HashSet<>();
    for (JsonElement entry : events) eventKeys.add(str(entry.getAsJsonObject(), "eventId"));
    for (JsonObject entry : capturedEvents) eventKeys.add(str(entry, "eventId"));
    clearedEvents.retainAll(eventKeys);
    origins.clear();
    if (root.has("origins"))
      for (JsonElement e : root.getAsJsonArray("origins")) {
        JsonObject o = e.getAsJsonObject();
        origins.put(str(o, "connectionId"), o);
      }
    updating = true;
    connectionRows.setRowCount(0);
    int selectedIndex = -1;
    for (int i = 0; i < flows.size(); i++) {
      JsonObject c = flows.get(i).getAsJsonObject();
      JsonObject origin = origins.get(str(c, "connectionId"));
      connectionRows.addRow(new Object[] {time(number(c, "validFromEpochMs")), number(c, "pid"),
          number(c, "uid"), str(c, "appName"), str(c, "processName"),
          endpoint(c, "clientIp", "clientPort"), endpoint(c, "serverIp", "serverPort"),
          str(c, "closed").equals("true") ? "Closed" : "Observed open",
          origin == null                           ? "Not captured / Evicted"
              : str(origin, "syscallPc").isEmpty() ? str(origin, "status")
                                                   : str(origin, "syscallPc"),
          time(number(c, "validToEpochMs") - (str(c, "closed").equals("true") ? 1 : 0))});
      if (str(c, "connectionId").equals(selected))
        selectedIndex = i;
    }
    if (selectedIndex >= 0) {
      int view = connections.convertRowIndexToView(selectedIndex);
      if (view >= 0)
        connections.setRowSelectionInterval(view, view);
      else
        selected = null;
    } else
      selected = null;
    updating = false;
    boolean stale = System.currentTimeMillis() - number(root, "updatedAtEpochMs") > 5000;
    status.setText((!str(root, "running").equals("true") ? "Stopped"
                           : stale                       ? "Disconnected"
                                                         : "Monitoring")
        + "   |   " + flows.size() + " connections   |   " + copies.size() + " packets");
    status.setToolTipText(file.toString() + " | Dropped snapshots: " + number(root, "originDrops")
        + " | Dropped packets: " + number(root, "copyDrops"));
    renderDetails();
  }
  private void renderDetails() {
    JsonObject owner = null;
    for (JsonElement e : flows) {
      JsonObject c = e.getAsJsonObject();
      if (str(c, "connectionId").equals(selected))
        owner = c;
    }
    details.setText(owner == null ? "Select a connection"
                                  : "App       " + str(owner, "appName") + "\nProcess   "
                + str(owner, "processName") + "\nPID       " + str(owner, "pid") + "\nUID       "
                + str(owner, "uid") + "\nTID       " + str(owner, "tid")
                + " (connect)\n\nClient    " + endpoint(owner, "clientIp", "clientPort")
                + "\nServer    " + endpoint(owner, "serverIp", "serverPort"));
    details.setCaretPosition(0);
    renderOrigin();
    renderEvents();
    // Preserve packet selection across live refresh by packet identity.
    int old = packets.getSelectedRow();
    String key = old >= 0 && old < visibleCopies.size() ? visibleCopies.get(old).toString() : null;
    visibleCopies.clear();
    packetRows.setRowCount(0);
    bytes.setText("");
    int choose = -1;
    packetScope.setText(owner == null ? "Select a connection"
                                      : endpoint(owner, "clientIp", "clientPort") + " <-> "
                + endpoint(owner, "serverIp", "serverPort"));
    packetScope.setToolTipText(selected);
    for (JsonElement e : copies) {
      JsonObject p = e.getAsJsonObject();
      String id = str(p, "connectionId");
      if (selected == null || !selected.equals(id) || clearedPackets.contains(p.toString()))
        continue;
      visibleCopies.add(p);
      byte[] b = Base64.getDecoder().decode(str(p, "data"));
      String direction = "";
      if (owner != null && id.equals(selected))
        direction =
            displayEndpoint(str(p, "source")).equals(endpoint(owner, "clientIp", "clientPort"))
            ? "\u2192"
            : "\u2190";
      packetRows.addRow(new Object[] {time(number(p, "atEpochMs")), str(p, "protocol"),
          displayEndpoint(str(p, "source")), displayEndpoint(str(p, "destination")),
          number(p, "originalLength"), direction});
      if (p.toString().equals(key))
        choose = visibleCopies.size() - 1;
    }
    if (choose >= 0)
      packets.setRowSelectionInterval(choose, choose);
  }
  private JComponent createEventsPanel() {
    eventRows = rows("Time", "Operation", "TID", "PC", "Length", "Status");
    ioEvents = new JTable(eventRows);
    ioEvents.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    ioEvents.setAutoCreateRowSorter(true);
    styleTable(ioEvents);
    clearMenu(ioEvents, this::clearEvents);
    eventView = new DebuggerView();
    eventView.setEventMode(0);
    FridaStream.initialize();
    ioEvents.getSelectionModel().addListSelectionListener(e -> {
      if (updatingEvents || e.getValueIsAdjusting())
        return;
      int row = ioEvents.getSelectedRow();
      selectedEvent =
          row < 0 ? null : str(visibleEvents.get(ioEvents.convertRowIndexToModel(row)), "eventId");
      renderSelectedEvent();
    });
    JComponent snapshots = eventView;
    JSplitPane split =
        new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(ioEvents), snapshots);
    split.setResizeWeight(.45);
    JPanel result = new JPanel(new BorderLayout());
    eventScope = new JLabel("Select a connection, then an I/O event");
    JPanel toolbar = new JPanel(new BorderLayout());
    JPanel settings = new JPanel(new FlowLayout(FlowLayout.LEFT));
    settings.add(new JLabel("Analysis mode: Settings"));
    JButton stopCapture = UiLayout.button("Stop");
    settings.add(stopCapture);
    stopCapture.addActionListener(e -> {
      if (stream != null)
        stream.stop();
      streamStatus = "Stopped";
      renderEvents();
    });
    toolbar.add(settings, BorderLayout.WEST);
    toolbar.add(eventScope);
    result.add(toolbar, BorderLayout.NORTH);
    result.add(split);
    eventMode.addActionListener(e -> {
      eventView.setEventMode(eventMode.getSelectedIndex());
      updateBrowserTab();
      renderedEvent = null;
      updateStream();
      renderEvents();
    });
    ioEvents.setToolTipText(
        "None / Manual shows TCP call entry. Frida shows syscall completion for all TIDs in the "
        + "selected PID. Length is the TCP call length; select an event for its result.");
    return result;
  }
  private String eventTime(JsonObject event) {
    if (event.has("capturedAtEpochMs"))
      return time(number(event, "capturedAtEpochMs"));
    String id = str(event, "connectionId");
    for (JsonElement entry : flows) {
      JsonObject c = entry.getAsJsonObject();
      if (!id.equals(str(c, "connectionId")))
        continue;
      try {
        long startNs = Long.parseLong(id.substring(id.lastIndexOf('/') + 1));
        long eventNs = Long.parseLong(str(event, "capturedAtBootNs"));
        return time(number(c, "validFromEpochMs") + eventNs / 1000000 - startNs / 1000000);
      } catch (NumberFormatException ignored) {
        return "";
      }
    }
    return "";
  }
  private void renderEvents() {
    updateStream();
    updatingEvents = true;
    eventRows.setRowCount(0);
    visibleEvents.clear();
    int choose = -1;
    boolean live = eventMode.getSelectedIndex() == 2;
    for (int i = (live ? capturedEvents.size() : events.size()) - 1; i >= 0; i--) {
      JsonObject event = live ? capturedEvents.get(i) : events.get(i).getAsJsonObject();
      if (!live && (selected == null || !selected.equals(str(event, "connectionId"))))
        continue;
      if (clearedEvents.contains(str(event, "eventId")))
        continue;
      visibleEvents.add(event);
      eventRows.addRow(
          new Object[] {eventTime(event), str(event, "operation"), number(event, "tid"),
              str(event, "syscallPc").isEmpty() ? "N/A"
                                                : DebuggerView.displayAddress(str(event, "syscallPc")),
              str(event, "requestedIoBytes"), str(event, "status")});
      if (str(event, "eventId").equals(selectedEvent))
        choose = visibleEvents.size() - 1;
    }
    if (choose >= 0) {
      int view = ioEvents.convertRowIndexToView(choose);
      if (view >= 0)
        ioEvents.setRowSelectionInterval(view, view);
      else
        selectedEvent = null;
    } else
      selectedEvent = null;
    updatingEvents = false;
    eventScope.setText(live    ? streamStatus + " / " + visibleEvents.size() + " events"
            : selected == null ? "Select a connection"
                               : visibleEvents.size() + " events");
    renderSelectedEvent();
  }
  private void renderSelectedEvent() {
    JsonObject chosen = null;
    for (JsonObject event : visibleEvents)
      if (str(event, "eventId").equals(selectedEvent)) {
        chosen = event;
        break;
      }
    String key = selectedEvent + "/" + (chosen == null ? "missing" : chosen.toString());
    if (key.equals(renderedEvent))
      return;
    renderedEvent = key;
    if (eventMode.getSelectedIndex() == 2)
      eventView.showRecorded(chosen);
    else
      eventView.showSnapshot(chosen);
  }
  private void renderOrigin() {
    JsonObject o = origins.get(selected);
    String key = selected + "/" + (o == null ? "missing" : o.toString());
    if (key.equals(renderedOrigin))
      return;
    renderedOrigin = key;
    connectView.showSnapshot(o);
  }
  private static String hex(JsonObject packet) {
    byte[] data = Base64.getDecoder().decode(str(packet, "data"));
    StringBuilder out = new StringBuilder();
    if (number(packet, "originalLength") > data.length)
      out.append(
          "Showing " + data.length + " of " + number(packet, "originalLength") + " bytes.\n\n");
    for (int i = 0; i < data.length; i += 16) {
      out.append(String.format("%04x  ", i));
      for (int j = 0; j < 16; j++)
        out.append(i + j < data.length ? String.format("%02x ", data[i + j] & 255) : "   ");
      out.append(" ");
      for (int j = i; j < Math.min(i + 16, data.length); j++) {
        int b = data[j] & 255;
        out.append(b >= 32 && b < 127 ? (char) b : '.');
      }
      out.append('\n');
    }
    return out.toString();
  }
}
