package ebpfproxy;

import java.awt.*;
import java.nio.file.*;
import java.util.prefs.Preferences;
import javax.swing.*;

final class AnalyzerSettings {
  static String jadxPath() {
    return System.getProperty("packetproxy.jadx.path",
        Preferences.userRoot().node("ebpfproxy").get("jadxPath", ""));
  }
  static void show(Component parent) {
    Object host = parent;
    while (host instanceof Component component) {
      if (component instanceof JComponent jc && jc.getClientProperty("ebpf.eventMode") instanceof JComboBox<?> mode) {
        @SuppressWarnings("unchecked") JComboBox<String> current = (JComboBox<String>) mode;
        show(parent, current);
        return;
      }
      host = component.getParent();
    }
    show(parent, null);
  }
  static void show(Component parent, JComboBox<String> currentMode) {
    SettingsForm form = new SettingsForm(currentMode);
    JTextField path = form.path;
    JComboBox<String> analysis = form.analysis;
    while (JOptionPane.showConfirmDialog(parent, form, "eBPF Analyzer Settings",
        JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) == JOptionPane.OK_OPTION) {
      String value = path.getText().trim();
      boolean valid;
      try { valid = value.isEmpty() || Files.isRegularFile(Path.of(value)); }
      catch (InvalidPathException ex) { valid = false; }
      if (!valid) {
        JOptionPane.showMessageDialog(parent, "Select an existing jadx CLI file.");
        continue;
      }
      Preferences prefs = Preferences.userRoot().node("ebpfproxy");
      prefs.put("jadxPath", value);
      try { prefs.flush(); }
      catch (java.util.prefs.BackingStoreException ex) {
        JOptionPane.showMessageDialog(parent, "Unable to save settings: " + ex.getMessage());
        continue;
      }
      System.setProperty("packetproxy.jadx.path", value);
      if (currentMode != null) currentMode.setSelectedIndex(analysis.getSelectedIndex());
      return;
    }
  }
  static final class SettingsForm extends JPanel {
    final JComboBox<String> analysis = new JComboBox<>(new String[] {"None", "Manual", "Frida"});
    final JTextField path = new JTextField(jadxPath(), 36);
    final JButton browse = UiLayout.button("Browse...");
    int row;
    SettingsForm(JComboBox<String> currentMode) {
      super(new GridBagLayout());
      setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
      UiLayout.combo(analysis);
      analysis.setSelectedIndex(currentMode == null ? 0 : currentMode.getSelectedIndex());
      if (currentMode != null) {
        heading("I/O analysis", 0);
        JPanel mode = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        mode.add(analysis); full(mode, 8);
        hint("Applies to this session. Frida collects future I/O stacks for the selected process and enables Modules / Java.");
      }
      heading("Java source", currentMode == null ? 0 : 18);
      full(new JLabel("jadx CLI executable"), 8);
      GridBagConstraints field = constraints(6);
      field.gridwidth = 1; field.weightx = 1; field.gridx = 0;
      path.setMinimumSize(new Dimension(160, path.getPreferredSize().height));
      add(path, field);
      GridBagConstraints button = constraints(6);
      button.gridx = 1; button.gridwidth = 1; button.weightx = 0;
      button.insets.left = 8; button.fill = GridBagConstraints.NONE;
      add(browse, button); row++;
      hint("Select bin/jadx.bat on Windows or bin/jadx on Linux/macOS. Use the CLI executable, not jadx-gui.");
      hint("Java Stack > Source reads the captured APK/DEX via ADB. You can also select a local file.");
      browse.addActionListener(e -> {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select jadx CLI (jadx / jadx.bat)");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
          path.setText(chooser.getSelectedFile().getAbsolutePath());
      });
    }
    GridBagConstraints constraints(int top) {
      GridBagConstraints c = new GridBagConstraints();
      c.gridx = 0; c.gridy = row; c.gridwidth = 2; c.weightx = 1;
      c.fill = GridBagConstraints.HORIZONTAL; c.anchor = GridBagConstraints.WEST;
      c.insets = new Insets(top, 0, 0, 0); return c;
    }
    void full(Component component, int top) { add(component, constraints(top)); row++; }
    void heading(String text, int top) {
      JLabel label = new JLabel(text);
      label.setFont(label.getFont().deriveFont(Font.BOLD)); full(label, top);
    }
    void hint(String text) {
      JTextArea area = new JTextArea(text, 2, 46);
      area.setFont(UIManager.getFont("Label.font"));
      area.setForeground(UIManager.getColor("Label.foreground"));
      area.setEditable(false); area.setFocusable(false); area.setOpaque(false);
      area.setLineWrap(true); area.setWrapStyleWord(true);
      area.setBorder(null); full(area, 8);
    }
  }

}
