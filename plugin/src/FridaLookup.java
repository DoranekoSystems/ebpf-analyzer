package ebpfproxy;

import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

final class FridaLookup {
  private static final java.util.concurrent.locks.ReentrantLock sessionLock =
      new java.util.concurrent.locks.ReentrantLock();
  static void initialize() {} // Load while the extension class loader is open.
  static JsonObject request(JsonObject snapshot, String action, Set<String> addresses)
      throws Exception {
    if (!sessionLock.tryLock())
      throw new IllegalStateException("Another Frida operation is running");
    try {
      return perform(snapshot, action, addresses);
    } finally {
      sessionLock.unlock();
    }
  }
  private static JsonObject perform(JsonObject snapshot, String action, Set<String> addresses)
      throws Exception {
    JsonObject request = new JsonObject();
    request.addProperty("action", action);
    request.add("snapshot", snapshot);
    request.addProperty("adb", System.getProperty("packetproxy.adb", "adb"));
    request.addProperty("serial", System.getProperty("packetproxy.adb.serial", "emulator-5554"));
    JsonArray list = new JsonArray();
    addresses.stream().limit(128).forEach(list::add);
    request.add("addresses", list);
    String script = System.getProperty("packetproxy.frida.script",
        Path.of(System.getProperty("user.home"), ".packetproxy", "extensions", "ebpf-frida",
                "bridge.py")
            .toString());
    if (!Files.isRegularFile(Path.of(script)))
      throw new IllegalStateException("Install the Frida bridge and Python frida-tools package");
    Process process =
        new ProcessBuilder(System.getProperty("packetproxy.frida.python", "python"), script)
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .start();
    CompletableFuture.delayedExecutor(60, TimeUnit.SECONDS).execute(() -> {
      if (process.isAlive())
        process.destroyForcibly();
    });
    try {
      try (var input = process.getOutputStream()) {
        input.write((request + "\n").getBytes(StandardCharsets.UTF_8));
      }
      byte[] output = process.getInputStream().readNBytes(4 * 1024 * 1024 + 1);
      if (output.length > 4 * 1024 * 1024)
        throw new IllegalStateException("Frida response exceeds limit");
      JsonObject result;
      try {
        result =
            JsonParser.parseString(new String(output, StandardCharsets.UTF_8)).getAsJsonObject();
      } catch (RuntimeException e) {
        throw new IllegalStateException(
            "Frida bridge unavailable; check Python, frida-tools and frida-server");
      }
      if (result.has("error"))
        throw new IllegalStateException(result.get("error").getAsString());
      return result;
    } finally {
      if (process.isAlive())
        process.destroyForcibly();
    }
  }
  static JsonObject resolve(JsonObject snapshot, Set<String> addresses, String disassemble)
      throws Exception {
    Set<String> all = new LinkedHashSet<>(addresses);
    if (snapshot.has("syscallPc"))
      all.add(snapshot.get("syscallPc").getAsString());
    JsonArray resolved = request(snapshot, "symbols", all).getAsJsonArray("results");
    // Attach/detach changes mappings. Establish the ELF continuation baseline afterwards.
    JsonObject result = SymbolLookup.resolve(snapshot, addresses, disassemble);
    Map<String, JsonObject> labels = new HashMap<>();
    for (JsonElement e : resolved) {
      JsonObject r = e.getAsJsonObject();
      labels.put(r.get("address").getAsString().toLowerCase(Locale.ROOT), r);
    }
    for (JsonElement e : result.getAsJsonArray("results")) {
      JsonObject r = e.getAsJsonObject(),
                 f = labels.get(r.get("address").getAsString().toLowerCase(Locale.ROOT));
      if (f != null && !f.get("symbol").getAsString().isEmpty()) {
        r.add("symbol", f.get("symbol"));
        r.add("module", f.get("module"));
      }
    }
    if (result.has("stackTrace"))
      for (JsonElement e : result.getAsJsonObject("stackTrace").getAsJsonArray("frames")) {
        JsonObject r = e.getAsJsonObject(),
                   f = labels.get(r.get("pc").getAsString().toLowerCase(Locale.ROOT));
        if (f != null && !f.get("symbol").getAsString().isEmpty()) {
          r.add("symbol", f.get("symbol"));
          r.add("module", f.get("module"));
        }
      }
    result.addProperty("scope",
        "Frida symbols from current process; historical stack uses saved bytes and ELF CFI; "
        + "disassembly reads ELF files");
    return result;
  }
}
