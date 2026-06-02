package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
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

        JMenuItem pasteItem = new JMenuItem("Paste cURL command");
        pasteItem.addActionListener((ActionEvent e) -> {
            //get cURL request from clipboard
            String curlRequest = getClipboardContent();
            api.logging().logToOutput("Parsing: " + curlRequest);

            //parse cURL into raw HTTP request
            HttpRequest rawRequest = parseCurlRequest(curlRequest);

            //open new HTTP request in repeater
            api.repeater().sendToRepeater(rawRequest);
        });

        menuItemList.add(pasteItem);
        return menuItemList;
    }

    private HttpRequest parseCurlRequest(String curlCommand) {
        CurlParser.CurlRequest curlRequest = CurlParser.parseCurlCommand(curlCommand, api);

        HttpService service = HttpService.httpService(curlRequest.getBaseUrl());

        // Build the request from the raw cURL data only. httpRequestFromUrl() would inject Burp's
        // default browser headers (User-Agent: Mozilla, Sec-*, Accept: text/html, ...); parsing a
        // raw request string adds nothing, so the result matches the copied cURL exactly.
        String target = curlRequest.getPath();
        if (curlRequest.getQuery() != null && !curlRequest.getQuery().isEmpty()) {
            target += "?" + curlRequest.getQuery();
        }

        StringBuilder raw = new StringBuilder();
        raw.append(curlRequest.getMethod()).append(" ").append(target).append(" HTTP/1.1\r\n");

        boolean hasHost = false;
        for (HttpHeader header : curlRequest.getHeaders()) {
            if ("host".equalsIgnoreCase(header.name())) hasHost = true;
            raw.append(header.name()).append(": ").append(header.value()).append("\r\n");
        }
        // A valid HTTP/1.1 request needs a Host line; add it only if the cURL command lacked one.
        if (!hasHost) {
            raw.append("Host: ").append(curlRequest.getHost()).append("\r\n");
        }
        raw.append("\r\n").append(curlRequest.getBody());

        return HttpRequest.httpRequest(service, raw.toString());
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
