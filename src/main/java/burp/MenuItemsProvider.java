package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class MenuItemsProvider implements ContextMenuItemsProvider {

    private MontoyaApi api;

    public MenuItemsProvider() {
        //noop
    }

    public MenuItemsProvider(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItemList = new ArrayList<>();

        CurlParser.CurlRequest curlRequest = CurlParser.parseCurlCommand(getClipboardContent(), api);
        if (curlRequest == null) {
            return menuItemList;
        }

        if (SettingsPanel.isEnabled(api, SettingsPanel.ENABLE_HTTP1)) {
            menuItemList.add(pasteMenuItem("HTTP/1.1", curlRequest.toHttp1Request()));
        }
        if (SettingsPanel.isEnabled(api, SettingsPanel.ENABLE_HTTP2)) {
            menuItemList.add(pasteMenuItem("HTTP/2", curlRequest.toHttp2Request()));
        }

        return menuItemList;
    }

    private JMenuItem pasteMenuItem(String label, HttpRequest request) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(e -> api.repeater().sendToRepeater(request));
        return item;
    }

    public String getClipboardContent() {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable transferable = clipboard.getContents(null);
        if (transferable != null && transferable.isDataFlavorSupported(DataFlavor.stringFlavor)) {
            try {
                return (String) transferable.getTransferData(DataFlavor.stringFlavor);
            } catch (UnsupportedFlavorException | IOException e) {
                api.logging().logToError(e);
            }
        }
        return "";
    }

}
