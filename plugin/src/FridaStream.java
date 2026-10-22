package ebpfproxy;
import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import javax.swing.SwingUtilities;

final class FridaStream {
  private volatile Process process;
  private volatile boolean stopped;
  private boolean initialized;
  static void initialize() {}
  synchronized void request(JsonObject request) throws IOException {
    if (stopped || !initialized || process == null || !process.isAlive()) throw new IOException("Frida collection is not running or is still attaching");
    process.getOutputStream().write((request + "\n").getBytes(StandardCharsets.UTF_8));
    process.getOutputStream().flush();
  }
  void start(JsonObject snapshot, Consumer<JsonObject> receive) {
    Thread worker = new Thread(() -> {
      try {
        String bridge = System.getProperty("packetproxy.frida.script",
            Path.of(System.getProperty("user.home"), ".packetproxy", "extensions", "ebpf-frida",
                    "bridge.py")
                .toString());
        process = new ProcessBuilder(System.getProperty("packetproxy.frida.python", "python"),
            Path.of(bridge).resolveSibling("stream.py").toString())
                      .redirectError(ProcessBuilder.Redirect.DISCARD)
                      .start();
        JsonObject request = new JsonObject();
        request.add("snapshot", snapshot);
        request.addProperty("adb", System.getProperty("packetproxy.adb", "adb"));
        request.addProperty(
            "serial", System.getProperty("packetproxy.adb.serial", "emulator-5554"));
        synchronized (this) {
          process.getOutputStream().write((request + "\n").getBytes(StandardCharsets.UTF_8));
          process.getOutputStream().flush();
          initialized = true;
        }
        if (stopped)
          stop();
        try (var reader = new BufferedReader(
                 new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
          String line;
          while ((line = reader.readLine()) != null) {
            JsonObject event = JsonParser.parseString(line).getAsJsonObject();
            if (!stopped)
              SwingUtilities.invokeAndWait(() -> {
                if (!stopped)
                  receive.accept(event);
              });
          }
        }
        if (!stopped)
          throw new IOException("Frida collection stopped");
      } catch (Exception e) {
        if (!stopped) {
          JsonObject error = new JsonObject();
          error.addProperty("type", "error");
          error.addProperty("error", e.getMessage());
          SwingUtilities.invokeLater(() -> {
            if (!stopped)
              receive.accept(error);
          });
        }
      } finally {
        stop();
      }
    }, "ebpf-frida-stream");
    worker.setDaemon(true);
    worker.start();
  }
  synchronized void stop() {
    stopped = true;
    Process p = process;
    if (p == null)
      return;
    try {
      p.getOutputStream().close();
    } catch (IOException ignored) {
    }
    CompletableFuture.delayedExecutor(10, TimeUnit.SECONDS).execute(() -> {
      if (p.isAlive())
        p.destroyForcibly();
    });
  }
}
