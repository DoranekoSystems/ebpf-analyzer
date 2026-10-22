package ebpfproxy;

import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

final class SymbolLookup {
  // Only immutable per-event results, bounded across both debugger views.
  private static final Map<String, JsonObject> cache = new LinkedHashMap<>(32, .75f, true) {
    protected boolean removeEldestEntry(Map.Entry<String, JsonObject> e) {
      return size() > 16;
    }
  };
  static synchronized JsonObject get(String key) {
    return cache.get(key);
  }
  static synchronized void put(String key, JsonObject value) {
    cache.put(key, value);
  }
  static String key(JsonObject snapshot) {
    return snapshot.get("connectionId").getAsString() + "/" + snapshot.get("pid").getAsString()
        + "/" + snapshot.get("capturedAtBootNs").getAsString();
  }
  static JsonObject resolve(JsonObject snapshot, Set<String> addresses) throws Exception {
    return resolve(snapshot, addresses,
        snapshot.has("syscallPc") ? snapshot.get("syscallPc").getAsString() : "");
  }
  static JsonObject resolve(JsonObject snapshot, Set<String> addresses, String disassemble)
      throws Exception {
    return resolve(snapshot, addresses, disassemble, null);
  }
  static JsonObject resolve(JsonObject snapshot, Set<String> addresses, String disassemble,
      JsonObject previous) throws Exception {
    return resolve(snapshot, addresses, disassemble, previous, false);
  }
  static JsonObject resolve(JsonObject snapshot, Set<String> addresses, String disassemble,
      JsonObject previous, boolean before) throws Exception {
    String connection = snapshot.get("connectionId").getAsString();
    String boot = connection.split("/")[0];
    if (!boot.matches("[0-9a-fA-F-]{36}"))
      throw new IllegalArgumentException("Capture has no valid device boot ID");
    JsonObject request = new JsonObject();
    request.addProperty("before", before);
    request.add("pid", snapshot.get("pid"));
    request.addProperty("bootId", boot);
    request.add("eventNs", snapshot.get("capturedAtBootNs"));
    JsonArray list = new JsonArray();
    addresses.stream().limit(128).forEach(list::add);
    request.add("addresses", list);
    if (previous == null) {
      JsonObject stack = new JsonObject();
      stack.add("base", snapshot.get("stackBase"));
      stack.add("data", snapshot.get("stack"));
      stack.add("registers", snapshot.get("registers"));
      stack.add("pc", snapshot.get("syscallPc"));
      request.add("stack", stack);
    } else {
      if (previous.has("codeMapping"))
        request.add("codeMapping", previous.get("codeMapping"));
      else
        request.add("mapsHash", previous.get("mapsHash"));
      request.add("fileId", previous.getAsJsonObject("disassembly").get("fileId"));
      request.addProperty("codeOnly", true);
    }
    if (!disassemble.isEmpty()) {
      request.addProperty("disassemble", disassemble);
      if (snapshot.has("syscallPc")
          && disassemble.equalsIgnoreCase(snapshot.get("syscallPc").getAsString())
          && snapshot.has("instructionHex"))
        request.add("expectedBytes", snapshot.get("instructionHex"));
    }
    String remote =
        System.getProperty("packetproxy.symbols.remote", "/data/local/tmp/ebpf-analyzer");
    if (!remote.matches("/[A-Za-z0-9/_.-]+"))
      throw new IllegalArgumentException("Invalid resolver path");
    Process p = new ProcessBuilder(System.getProperty("packetproxy.adb", "adb"), "-s",
        System.getProperty("packetproxy.adb.serial", "emulator-5554"), "shell", "-T", "su", "0",
        remote, "symbols")
                    .redirectErrorStream(true)
                    .start();
    CompletableFuture.delayedExecutor(15, TimeUnit.SECONDS).execute(() -> {
      if (p.isAlive())
        p.destroyForcibly();
    });
    try {
      try (var input = p.getOutputStream()) {
        input.write((request.toString() + "\n").getBytes(StandardCharsets.UTF_8));
      }
      byte[] output = p.getInputStream().readNBytes(4 * 1024 * 1024 + 1);
      if (output.length > 4 * 1024 * 1024)
        throw new IllegalStateException("Symbol response exceeds limit");
      if (!p.waitFor(1, TimeUnit.SECONDS) || p.exitValue() != 0)
        throw new IllegalStateException(
            "Resolver failed; check adb, root and the installed resolver");
      JsonObject result;
      try {
        result =
            JsonParser.parseString(new String(output, StandardCharsets.UTF_8)).getAsJsonObject();
      } catch (RuntimeException e) {
        throw new IllegalStateException("Resolver unavailable or invalid response");
      }
      if (result.has("error"))
        throw new IllegalStateException(result.get("error").getAsString());
      return result;
    } finally {
      if (p.isAlive())
        p.destroyForcibly();
    }
  }
}
