package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URL;
import org.apache.commons.text.StringEscapeUtils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Parses cURL request into strings.
 * 
 * @author August Detlefsen
 */
public class CurlParser {

    public static CurlRequest parseCurlCommand(String curlCommand) {
        return parseCurlCommand(curlCommand, null);
    }

    public static CurlRequest parseCurlCommand(String curlCommand, MontoyaApi api) {

        log("CurlParser.parseCurlCommand(): " + curlCommand, api);

        String requestMethod = "GET";
        String protocol = null;
        String host = null;
        String path = null;
        Integer port = null;
        String query = null;
        List<HttpHeader> headers = new ArrayList<>();
        String body = "";

        // Extract request method
        Pattern methodPattern = Pattern.compile("(?:--request|-X)\\s+([A-Z]+)");
        Matcher methodMatcher = methodPattern.matcher(curlCommand);
        if (methodMatcher.find()) {
            requestMethod = methodMatcher.group(1);
        }

        // Extract full URL
        Pattern pattern = Pattern.compile("([\\s'\"]?)(https?://.*?)");
        Matcher matcher = pattern.matcher(curlCommand);
        if (matcher.find()) {
            // Extract the delimiter
            String delimiter = matcher.group(1);

            // Check if the URL ends with the same delimiter
            if (delimiter != null && !delimiter.isEmpty()) {
                log("delimiter: |" + delimiter + "|", api);
                // Start looking after the delimiter
                int startIdx = matcher.end(1); // Skip the delimiter
                log("start: " + startIdx, api);
                int endIdx = startIdx;

                // Find the position where the URL ends
                for (int i = endIdx; i < curlCommand.length(); i++) {
                    if (curlCommand.charAt(i) == delimiter.charAt(0)) {
                        //endIdx = i;
                        break;
                    }
                    endIdx++;
                }

                log("end: " + endIdx, api);
                String extractedUrl = curlCommand.substring(startIdx, endIdx);
                log("url: " + extractedUrl, api);

                try {
                    URL url = new URL(extractedUrl);

                    protocol = url.getProtocol();
                    host = url.getHost();
                    path = url.getPath();
                    query = url.getQuery();
                    port = url.getPort();
                } catch (java.net.MalformedURLException mue) {
                    if (api != null) api.logging().logToError(mue);

                    return null;
                }
            }
        } else {
            return null;
        }

        // Extract headers
        Pattern headerPattern = Pattern.compile("(?:--header|-H)\\s+(?:'([^']*)'|\"([^\"]*)\"|(\\S+))");
        Matcher headerMatcher = headerPattern.matcher(curlCommand);
        while (headerMatcher.find()) {
            String header = headerMatcher.group(1);
            if (header == null) header = headerMatcher.group(2);
            if (header == null) header = headerMatcher.group(3);

            int colonIndex = header.indexOf(':');
            if (colonIndex != -1) {
                String name = header.substring(0, colonIndex).trim();
                String value = header.substring(colonIndex + 1).trim();
                if ("accept-encoding".equalsIgnoreCase(name) && isZstdDisabled(api)) {
                    value = removeZstd(value);
                }

                HttpHeader httpHeader = new HttpHeaderImpl(name, value);
                headers.add(httpHeader);
            }
        }

        //Extract cookies - Montoya treats cookies as just another header
        Pattern cookiePattern = Pattern.compile("(?:--cookie|-b)\\s+(?:['\"]([^'\"]+)['\"]|(\\S+))");
        Matcher cookieMatcher = cookiePattern.matcher(curlCommand);

        List<String> cookieValues = new ArrayList<>();
        while (cookieMatcher.find()) {
            String value = cookieMatcher.group(1) != null
                    ? cookieMatcher.group(1)
                    : cookieMatcher.group(2);
            cookieValues.add(value);
        }

        if (!cookieValues.isEmpty()) {
            List<String> normalized = new ArrayList<>();
            for (String c : cookieValues) {
                // Trim spaces and remove trailing semicolons/spaces
                String cleaned = c.trim().replaceAll("[;\\s]+$", "");
                normalized.add(cleaned);
            }

            // Combine all cookies using a single "; " separator
            String combinedCookies = String.join("; ", normalized);

            // Add as a Cookie header
            HttpHeader httpHeader = new HttpHeaderImpl("Cookie", combinedCookies);
            headers.add(httpHeader);
        }

        // Extract request body
        Pattern bodyPattern = Pattern.compile("(?:--data-raw|--data-binary|--data|-d)\\s+\\$?(['\"])(.*?)(\\1)", Pattern.DOTALL);
        Matcher bodyMatcher = bodyPattern.matcher(curlCommand);

        if (bodyMatcher.find()) {
            String rawBody = bodyMatcher.group(2);

            // Only unescape for $'...' dollar-quoted strings (bash C-style quoting)
            int quoteStart = bodyMatcher.start(1);
            boolean isDollarQuoted = quoteStart > 0 && curlCommand.charAt(quoteStart - 1) == '$';
            body = isDollarQuoted ? StringEscapeUtils.unescapeJava(rawBody) : rawBody;

            // If -X option is not specified and --data-raw is present, assume it's a POST request
            if (requestMethod == null || "GET".equals(requestMethod)) {
                requestMethod = "POST";
            }
        }

        if (api != null) {
            log("CurlParser.parseCurlCommand() complete: host: " + host + " path: " + path, api);
            log("Body: " + body, api);
        }

        if (host != null && path != null) {
            return new CurlRequest(requestMethod, protocol, host, path, query, port, headers, body);
        } else {
            return null;
        }
    }

    // Defaults to true (strip zstd) when there is no UI/preferences, e.g. unit tests.
    static boolean isZstdDisabled(MontoyaApi api) {
        if (api == null) {
            return true;
        }
        return SettingsPanel.isEnabled(api, SettingsPanel.DISABLE_ZSTD);
    }

    // Burp can't decode zstd, so strip it from accept-encoding to keep responses readable.
    static String removeZstd(String acceptEncoding) {
        return Arrays.stream(acceptEncoding.split(","))
                .map(String::trim)
                .filter(token -> !token.equalsIgnoreCase("zstd"))
                .collect(Collectors.joining(", "));
    }

    protected static void log(String toLog, MontoyaApi api) {
        if (api != null) {

        } else {
            System.out.println(toLog);
        }
    }

    static class CurlRequest {
        private final String method;
        private final String protocol;
        private final String host;
        private final String path;
        private final String query;
        private final Integer port;
        private final List<HttpHeader> headers;
        private final String body;

        public CurlRequest(String method, String protocol, String host, String path, String query, Integer port, List<HttpHeader> headers, String body) {
            this.method = method;
            this.protocol = protocol;
            this.host = host;
            this.path = path;
            this.query = query;
            this.port = port;
            this.headers = headers;
            this.body = body;
        }

        public String getBaseUrl() {
            StringBuilder builder = new StringBuilder();
            builder.append(getProtocol())
                   .append("://")
                   .append(getHost());

            if (port != -1 && port != 80 && port != 443) builder.append(":").append(getPort());

            builder.append(getPath());

            if (query != null && !"".equals(query)) builder.append("?").append(query);

            return builder.toString();
        }

        public String getMethod() {
            return method;
        }
        public String getProtocol() {
            return protocol;
        }
        public String getHost() {
            return host;
        }

        public String getPath() {
            if (path == null || "".equals(path)) return "/";

            return path;
        }

        public String getQuery() {
            return query;
        }

        public Integer getPort() {
            return port;
        }

        public List<HttpHeader> getHeaders() {
            return headers;
        }

        public String getBody() {
            return body;
        }

        public HttpRequest toHttp1Request() {
            HttpService service = HttpService.httpService(getBaseUrl());

            StringBuilder raw = new StringBuilder();
            raw.append(getMethod()).append(" ").append(pathWithQuery()).append(" HTTP/1.1\r\n");

            if (headers.stream().noneMatch(h -> "host".equalsIgnoreCase(h.name()))) {
                raw.append("Host: ").append(getHost()).append("\r\n");
            }
            for (HttpHeader header : headers) {
                raw.append(header.name()).append(": ").append(header.value()).append("\r\n");
            }
            raw.append("\r\n").append(getBody());

            return HttpRequest.httpRequest(service, raw.toString());
        }

        public HttpRequest toHttp2Request() {
            HttpService service = HttpService.httpService(getBaseUrl());

            List<HttpHeader> http2Headers = new ArrayList<>(headers);
            if (http2Headers.stream().noneMatch(h -> "host".equalsIgnoreCase(h.name()))) {
                http2Headers.add(0, new HttpHeaderImpl("Host", getHost()));
            }

            return HttpRequest.http2Request(service, http2Headers, getBody())
                    .withMethod(getMethod())
                    .withPath(pathWithQuery());
        }

        private String pathWithQuery() {
            if (query != null && !"".equals(query)) {
                return getPath() + "?" + query;
            }
            return getPath();
        }
    }
}
