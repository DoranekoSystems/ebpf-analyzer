package ebpfproxy;

import java.awt.*;
import javax.swing.*;

final class UiLayout {
  static JButton button(String text) {
    return new JButton(text) {
      public Dimension getPreferredSize() {
        Dimension size = super.getPreferredSize();
        Insets insets = getInsets();
        int width = getFontMetrics(getFont()).stringWidth(getText()) + insets.left + insets.right + 14;
        if (getIcon() != null) width += getIcon().getIconWidth() + getIconTextGap();
        return new Dimension(Math.max(size.width, width), Math.max(size.height,
            getFontMetrics(getFont()).getHeight() + insets.top + insets.bottom + 4));
      }
      public Dimension getMinimumSize() { return getPreferredSize(); }
    };
  }
  static void combo(JComboBox<String> combo) {
    combo.setPrototypeDisplayValue("  Manual  ");
    combo.setMinimumSize(combo.getPreferredSize());
  }
  static JScrollPane horizontal(Component content) {
    JScrollPane pane = new JScrollPane(content, ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER,
        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
    pane.setBorder(null);
    pane.setMinimumSize(new Dimension(0, 0));
    pane.setPreferredSize(new Dimension(content.getPreferredSize().width, content.getPreferredSize().height + 14));
    return pane;
  }
}
