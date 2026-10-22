package ebpfproxy;

import com.google.gson.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.tree.*;

public class ProcessBrowserTest {
  static TreePath find(JTree tree, String owner, String method) {
    DefaultMutableTreeNode root = (DefaultMutableTreeNode) tree.getModel().getRoot();
    Enumeration<?> nodes = root.depthFirstEnumeration();
    while (nodes.hasMoreElements()) {
      DefaultMutableTreeNode node = (DefaultMutableTreeNode) nodes.nextElement();
      if (node.getUserObject() instanceof ProcessBrowser.Entry entry && entry.owner.equals(owner) && entry.method.equals(method)) return new TreePath(node.getPath());
    }
    throw new AssertionError("Missing tree entry: " + owner + "/" + method);
  }
  static Object field(Object object, String name) throws Exception {
    var field = object.getClass().getDeclaredField(name); field.setAccessible(true); return field.get(object);
  }
  static void layout(Container component) {
    component.doLayout();
    for (Component child : component.getComponents()) if (child instanceof Container nested) layout(nested);
  }
  public static void main(String[] args) throws Exception {
    SwingUtilities.invokeAndWait(() -> {
      try {
        List<JsonObject> requests = new ArrayList<>(); List<String> selected = new ArrayList<>();
        ProcessBrowser view = new ProcessBrowser(requests::add, selected::add);
        view.reset(42);
        view.accept(JsonParser.parseString("{\"type\":\"catalog\",\"modules\":[{\"name\":\"libnet.so\",\"path\":\"/lib/libnet.so\"}],\"classes\":[\"com.example.Client\",\"com.example.Idle\"]}").getAsJsonObject());
        JsonObject event = JsonParser.parseString("{\"eventId\":\"event1\",\"tid\":43,\"operation\":\"send\",\"nativeFrames\":[{\"module\":\"/lib/libnet.so\",\"symbolName\":\"send\"}],\"java\":{\"frames\":[{\"className\":\"com.example.Client\",\"methodName\":\"request\",\"origin\":\"/data/app/base.apk\"},{\"className\":\"com.example.Client\",\"methodName\":\"request\"}]}}").getAsJsonObject();
        view.setEvents(List.of(event)); view.refresh.stop(); view.rebuild();
        view.javaTree.setSelectionPath(find(view.javaTree, "com.example.Client", "request"));
        if (view.matches.getRowCount() != 1 || view.selected.events.size() != 1) throw new AssertionError("duplicate frames counted as calls");
        view.table.setRowSelectionInterval(0, 0); view.openSelected();
        if (!selected.equals(List.of("event1"))) throw new AssertionError("event navigation");
        if (!requests.isEmpty()) throw new AssertionError("observed frames requested full inventory");
        if (!DebuggerView.str(view.selected.frame, "origin").equals("/data/app/base.apk")) throw new AssertionError("source origin lost");
        if (!view.index.get("module\n/lib/libnet.so\n").toString().startsWith("libnet.so")) throw new AssertionError("module label");
        view.firstFrame.setValue(1); view.lastFrame.setValue(1);
        find(view.javaTree, "com.example.Client", "request");
        if (!view.index.get("module\n/lib/libnet.so\n").events.isEmpty()) throw new AssertionError("native depth filter");
        view.firstFrame.setValue(2);
        if (!view.index.get("class\ncom.example.Client\n").events.isEmpty()) throw new AssertionError("Java depth filter");
        view.firstFrame.setValue(0); view.lastFrame.setValue(0);
        view.observedOnly.setSelected(false); view.rebuild();
        view.javaTree.expandPath(find(view.javaTree, "com.example.Idle", ""));
        if (requests.stream().noneMatch(r -> DebuggerView.str(r, "name").equals("com.example.Idle"))) throw new AssertionError("lazy class members missing");
        view.accept(JsonParser.parseString("{\"type\":\"members\",\"kind\":\"class\",\"name\":\"com.example.Client\",\"members\":[\"request(int): void\",\"request(): void\",\"idle(): void\"]}").getAsJsonObject());
        find(view.javaTree, "com.example.Client", "idle");
        view.observedOnly.setSelected(true); view.rebuild();
        try { find(view.javaTree, "com.example.Client", "idle"); throw new AssertionError("unobserved member not filtered"); }
        catch (AssertionError ex) { if (!ex.getMessage().startsWith("Missing tree entry")) throw ex; }
        view.javaTree.setSelectionPath(find(view.javaTree, "com.example.Client", "request"));
        JsonObject offsetEvent = event.deepCopy();
        offsetEvent.addProperty("eventId", "event2");
        JsonObject first = event.getAsJsonArray("nativeFrames").get(0).getAsJsonObject();
        first.addProperty("address", "0x1002"); first.addProperty("functionOffset", "0x2");
        JsonObject second = offsetEvent.getAsJsonArray("nativeFrames").get(0).getAsJsonObject();
        second.addProperty("address", "0x1010"); second.addProperty("functionOffset", "0x10");
        event.getAsJsonArray("nativeFrames").add(first.deepCopy());
        view.setEvents(List.of(event, offsetEvent)); view.refresh.stop(); view.rebuild();
        TreePath function = find(view.libraries, "/lib/libnet.so", "send").getParentPath();
        // find() visits offset leaves first; select the function parent explicitly.
        DefaultMutableTreeNode functionNode = (DefaultMutableTreeNode) function.getLastPathComponent();
        if (!(functionNode.getUserObject() instanceof ProcessBrowser.Entry functionEntry) || !functionEntry.offset.isEmpty()) throw new AssertionError("offset hierarchy");
        if (functionNode.getChildCount() != 2 || !functionNode.getChildAt(0).toString().equals("+0x2") || !functionNode.getChildAt(1).toString().equals("+0x10")) throw new AssertionError("numeric offset ordering");

        TreePath offset = function.pathByAddingChild(functionNode.getChildAt(1));
        view.libraries.expandPath(function); view.libraries.setSelectionPath(offset);
        if (view.matches.getRowCount() != 1 || !view.matchingIds.equals(List.of("event2"))) throw new AssertionError("offset reverse lookup");
        int offsetRow = view.libraries.getRowForPath(offset);
        if (view.libraryTable.getSelectedRow() != offsetRow) throw new AssertionError("table selection differs from offset");
        if (view.libraryTable.getColumnCount() != 1) throw new AssertionError("Counter still visible");
        view.libraryTable.toggle(function);
        int collapsedRows = view.libraryTable.getRowCount();
        view.rebuild();
        function = find(view.libraries, "/lib/libnet.so", "send").getParentPath();
        if (view.libraries.isExpanded(function) || view.libraryTable.getRowCount() != collapsedRows) throw new AssertionError("collapse lost on refresh");
        view.libraryTable.toggle(function);
        if (view.libraryTable.getRowCount() != collapsedRows + 2) throw new AssertionError("expand offsets");
        view.libraries.setSelectionPath(function.pathByAddingChild(((DefaultMutableTreeNode) function.getLastPathComponent()).getChildAt(0)));
        if (!ProcessBrowser.nativeOffset(JsonParser.parseString("{\"symbol\":\"lib.so!send+0x000a\"}").getAsJsonObject()).equals("+0xa")) throw new AssertionError("legacy offset parsing");
        if (!ProcessBrowser.nativeOffset(new JsonObject()).equals("Offset unavailable")) throw new AssertionError("invented offset");
        JsonObject namedOffset = JsonParser.parseString("{\"symbolName\":\"send+0x3b\"}").getAsJsonObject();
        if (!ProcessBrowser.nativeName(namedOffset).equals("send") || !ProcessBrowser.nativeOffset(namedOffset).equals("+0x3b")) throw new AssertionError("function suffix not separated");
        if (!view.matches.getValueAt(0, 3).equals("Native #0, #1")) throw new AssertionError("matching frame indices");
        event.addProperty("result", 128); event.addProperty("resultUnit", "bytes");
        if (!ProcessBrowser.ioResult(event).equals("128 bytes")) throw new AssertionError("byte result");
        offsetEvent.addProperty("result", -11);
        if (!ProcessBrowser.ioResult(offsetEvent).equals("Error (errno 11)")) throw new AssertionError("error result");
        TreePath module = function.getParentPath();
        view.libraries.collapsePath(module); view.rebuild();
        module = find(view.libraries, "/lib/libnet.so", "send").getParentPath().getParentPath();
        if (view.libraries.isExpanded(module)) throw new AssertionError("nested collapse reopened on refresh");
        view.libraries.expandPath(module);
        function = find(view.libraries, "/lib/libnet.so", "send").getParentPath();
        if (!view.libraries.isExpanded(function)) throw new AssertionError("hidden nested expansion was lost");
        view.libraries.setSelectionPath(module); view.libraryTable.branch(false); view.rebuild();
        function = find(view.libraries, "/lib/libnet.so", "send").getParentPath();
        module = function.getParentPath(); view.libraries.expandPath(module);
        if (view.libraries.isExpanded(function)) throw new AssertionError("recursive collapse failed");
        view.libraries.setSelectionPath(module); int requestCount = requests.size(); view.libraryTable.branch(true);
        if (!view.libraries.isExpanded(function) || requests.size() != requestCount) throw new AssertionError("recursive expansion fetched inventory or failed");
        view.libraries.setSelectionPath(function); view.updateMatches();
        view.libraryTable.autoExpand.setSelectedIndex(0);
        function = find(view.libraries, "/lib/libnet.so", "send").getParentPath();
        if (!view.libraries.isExpanded(function)) throw new AssertionError("automatic expand");
        view.libraries.setSelectionPath(function);
        ((JMenuItem) view.libraryTable.menu.getComponent(3)).doClick(); view.rebuild();
        function = find(view.libraries, "/lib/libnet.so", "send").getParentPath();
        if (view.libraries.isExpanded(function)) throw new AssertionError("context collapse not preserved");
        view.libraryTable.autoExpand.setSelectedIndex(1);
        function = find(view.libraries, "/lib/libnet.so", "send").getParentPath();
        if (view.libraries.isExpanded(function.getParentPath())) throw new AssertionError("automatic collapse");
        view.libraryTable.autoExpand.setSelectedIndex(0);
        function = find(view.libraries, "/lib/libnet.so", "send").getParentPath();
        view.libraries.setSelectionPath(function);
        view.setSize(1200, 650); layout(view);
        BufferedImage image = new BufferedImage(1200, 650, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = image.createGraphics(); view.paint(graphics); graphics.dispose();
        ImageIO.write(image, "png", Path.of("plugin/build/tests/process-browser.png").toFile());
        JTabbedPane hierarchyTabs = (JTabbedPane) SwingUtilities.getAncestorOfClass(JTabbedPane.class, view.javaSourceTable);
        hierarchyTabs.setSelectedIndex(1);
        view.javaTree.clearSelection(); view.javaSourceTable.branch(true); layout(view);
        graphics = image.createGraphics(); view.paint(graphics); graphics.dispose();
        ImageIO.write(image, "png", Path.of("plugin/build/tests/process-browser-java.png").toFile());
        hierarchyTabs.setSelectedIndex(0);
        offsetEvent.addProperty("operation", "receive");
        view.setEvents(List.of(event, offsetEvent)); view.refresh.stop(); view.rebuild();
        view.libraries.setSelectionPath(find(view.libraries, "/lib/libnet.so", "send").getParentPath());
        view.direction.setSelectedIndex(1);
        if (!view.matchingIds.equals(List.of("event1"))) throw new AssertionError("send filter");
        view.direction.setSelectedIndex(2);
        if (!view.matchingIds.equals(List.of("event2"))) throw new AssertionError("receive filter");
        view.direction.setSelectedIndex(0);
        if (view.matches.getRowCount() != 2) throw new AssertionError("both directions");
        DebuggerView eventDebugger = new DebuggerView();
        eventDebugger.resolving = true; // Keep this UI regression test offline.
        eventDebugger.setEventMode(2);
        JsonObject recorded = event.deepCopy();
        recorded.addProperty("connectionId", "test/run/1"); recorded.addProperty("capturedAtBootNs", "1");
        recorded.addProperty("pid", 42); recorded.addProperty("stack", ""); recorded.addProperty("stackBase", "0x1000");
        recorded.addProperty("syscallPc", "0x123"); recorded.addProperty("capturedAtEpochMs", 0);
        recorded.add("registers", JsonParser.parseString("{\"rip\":\"0x125\",\"rsp\":\"0x1000\",\"rflags\":\"0x246\"}"));
        eventDebugger.showRecorded(recorded);
        JTabbedPane capturedTabs = (JTabbedPane) eventDebugger.fridaView.getComponent(1);
        capturedTabs.setSelectedIndex(1);
        eventDebugger.showRecorded(recorded.deepCopy());
        if (eventDebugger.stackTabs.getSelectedComponent() != eventDebugger.fridaView || capturedTabs.getSelectedIndex() != 1) throw new AssertionError("captured Java tab reset");
        eventDebugger.stackTabs.setSelectedComponent(eventDebugger.disassemblyPanel);
        eventDebugger.showRecorded(recorded.deepCopy());
        if (eventDebugger.stackTabs.getSelectedComponent() != eventDebugger.disassemblyPanel) throw new AssertionError("disassembly tab reset");
        eventDebugger.showRecorded(null); eventDebugger.showRecorded(recorded);
        if (eventDebugger.stackTabs.getSelectedComponent() != eventDebugger.disassemblyPanel) throw new AssertionError("tab lost across empty selection");
        if (!eventDebugger.registerRows.getValueAt(0, 1).equals("0x0000000000000123") || !eventDebugger.registerRows.getValueAt(1, 1).equals("0x0000000000000125")) throw new AssertionError("register padding");
        if (!DebuggerView.registerValue("0XFFFFFFFFFFFFFFFF").equals("0xffffffffffffffff")) throw new AssertionError("unsigned register padding");
        eventDebugger.showRecorded(null);
        view.clear();
        if (!view.index.isEmpty() || view.matches.getRowCount() != 0) throw new AssertionError("Clear left visible entries");
        view.setEvents(List.of(event, offsetEvent)); view.refresh.stop(); view.rebuild();
        if (!view.events.isEmpty() || !view.index.isEmpty()) throw new AssertionError("cleared events reappeared");
        view.accept(JsonParser.parseString("{\"type\":\"catalog\",\"classes\":[\"Old.Class\"]}").getAsJsonObject());
        if (!view.index.isEmpty()) throw new AssertionError("in-flight catalog restored cleared view");
        JsonObject newEvent = event.deepCopy(); newEvent.addProperty("eventId", "after-clear");
        view.setEvents(List.of(event, offsetEvent, newEvent)); view.refresh.stop(); view.rebuild();
        if (!view.events.keySet().equals(Set.of("after-clear"))) throw new AssertionError("new event lost after clear");
        view.observedOnly.setSelected(false); view.clear(); view.rebuild();
        if (!view.index.isEmpty()) throw new AssertionError("Clear did not empty full catalog mode");
        AnalyzerSettings.SettingsForm settings = new AnalyzerSettings.SettingsForm(new JComboBox<>(new String[] {"None", "Manual", "Frida"}));
        JOptionPane settingsPane = new JOptionPane(settings, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);
        settingsPane.setSize(settingsPane.getPreferredSize()); layout(settingsPane);
        if (settings.path.getWidth() < 160 || settings.browse.getWidth() < settings.browse.getPreferredSize().width
            || settings.path.getBounds().intersects(settings.browse.getBounds())) throw new AssertionError("Settings controls overlap or clip");
        BufferedImage settingsImage = new BufferedImage(settingsPane.getWidth(), settingsPane.getHeight(), BufferedImage.TYPE_INT_RGB);
        Graphics2D settingsGraphics = settingsImage.createGraphics(); settingsPane.paint(settingsGraphics); settingsGraphics.dispose();
        ImageIO.write(settingsImage, "png", Path.of("plugin/build/tests/settings.png").toFile());
        view.setEvents(List.of()); view.refresh.stop(); view.rebuild();
        if (view.matches.getRowCount() != 0) throw new AssertionError("stale matches after eviction");
        view.reset(99);
        if (!view.events.isEmpty() || !view.members.isEmpty() || !view.index.isEmpty()) throw new AssertionError("PID state leaked");
        DebuggerView debugger = new DebuggerView();
        debugger.frameRows.setColumnIdentifiers(new String[] {"Frame", "PC", "SP", "Source", "Symbol", "Path"});
        debugger.frameRows.addRow(new Object[] {0, "0x00000123", "", "", "old", "old"});
        debugger.snapshot = JsonParser.parseString("{\"nativeFrames\":[{\"address\":\"0x123\",\"symbol\":\"0x123 libnet.so!send\",\"module\":\"/lib/libnet.so\"}]}").getAsJsonObject();
        debugger.applyCapturedSymbols();
        if (!debugger.frameRows.getValueAt(0, 4).equals("libnet.so!send") || !debugger.frameRows.getValueAt(0, 5).equals("/lib/libnet.so")) throw new AssertionError("captured symbol/path mismatch");
        CommunicationOrigins plugin = new CommunicationOrigins();
        JComponent panel = plugin.createPanel();
        @SuppressWarnings("unchecked") JComboBox<String> mode = (JComboBox<String>) field(plugin, "eventMode");
        JTabbedPane tabs = (JTabbedPane) field(plugin, "tabs");
        ProcessBrowser browser = (ProcessBrowser) field(plugin, "processBrowser");
        if (SwingUtilities.isDescendingFrom(mode, panel)) throw new AssertionError("mode selector still on main panel");
        if (((DebuggerView) field(plugin, "connectView")).symbolMode.getItemCount() != 2) throw new AssertionError("Connect still exposes Frida");
        mode.setSelectedIndex(2);
        if (tabs.indexOfComponent(browser) < 0) throw new AssertionError("Frida tab missing");
        mode.setSelectedIndex(1);
        if (tabs.indexOfComponent(browser) >= 0) throw new AssertionError("Frida tab visible outside Frida mode");
        JButton button = UiLayout.button("Settings");
        button.setFont(button.getFont().deriveFont(24f));
        if (button.getPreferredSize().width < button.getFontMetrics(button.getFont()).stringWidth(button.getText()) + button.getInsets().left + button.getInsets().right)
          throw new AssertionError("button text clipped at larger font size");
      } catch (Exception ex) { throw new RuntimeException(ex); }
    });
    System.out.println("PASS: reverse lookup, deduplication, lazy members, observed filter, event navigation, PID reset, Settings-only mode, Frida-only tab, button sizing");
  }
}
