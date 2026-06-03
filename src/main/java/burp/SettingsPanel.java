package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import javax.swing.*;
import java.awt.*;

/**
 * Suite tab holding the Paste cURL configuration. The checkbox values are stored in Burp's
 * global Preferences, so they survive between sessions.
 */
public class SettingsPanel extends JPanel {

    static final String ENABLE_HTTP1 = "pastecurl.enableHttp1";
    static final String ENABLE_HTTP2 = "pastecurl.enableHttp2";
    static final String DISABLE_ZSTD = "pastecurl.disableZstd";

    public SettingsPanel(MontoyaApi api) {
        Preferences preferences = api.persistence().preferences();

        JCheckBox http1 = new JCheckBox("Enable HTTP/1.1", isEnabled(api, ENABLE_HTTP1));
        http1.addActionListener(e -> preferences.setBoolean(ENABLE_HTTP1, http1.isSelected()));

        JCheckBox http2 = new JCheckBox("Enable HTTP/2", isEnabled(api, ENABLE_HTTP2));
        http2.addActionListener(e -> preferences.setBoolean(ENABLE_HTTP2, http2.isSelected()));

        JCheckBox zstd = new JCheckBox("Compression: Disable zstd", isEnabled(api, DISABLE_ZSTD));
        zstd.addActionListener(e -> preferences.setBoolean(DISABLE_ZSTD, zstd.isSelected()));

        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.NORTHWEST;
        c.gridx = 0;
        c.insets = new Insets(8, 8, 0, 8);

        c.gridy = 0;
        add(http1, c);
        c.gridy = 1;
        add(http2, c);
        c.gridy = 2;
        add(zstd, c);

        c.gridy = 3;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        add(Box.createGlue(), c);
    }

    static boolean isEnabled(MontoyaApi api, String key) {
        Boolean value = api.persistence().preferences().getBoolean(key);
        if (value == null) {
            return true;
        }
        return value;
    }
}
