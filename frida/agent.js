// Java bridge is supplied by the installed frida-tools package, not vendored.
const Java = bridge;
let targetTid = 0,
  armed = false,
  continuous = false;
let javaStatus = 'Not initialized';
const functionStarts = new Map();

function functionOffset(address, symbol, module) {
  if (!module || !symbol.name) return '';
  try {
    const name = symbol.name.replace(/\s*\+0x[0-9a-f]+$/i, '');
    const key = module.path + ':' + module.base + ':' + name;
    if (!functionStarts.has(key)) {
      if (functionStarts.size >= 4096) functionStarts.clear();
      functionStarts.set(key, module.findSymbolByName(name));
    }
    const start = functionStarts.get(key);
    if (start === null || start.compare(module.base) < 0 || start.compare(address) > 0) return '';
    return address.sub(start).toString();
  } catch (_) { return ''; }
}

rpc.exports = {
  catalog() {
    const modules = Process.enumerateModules();
    let classes = [], javaError = '';
    if (Java.available) {
      try { Java.performNow(() => { classes = Array.from(new Set(Java.enumerateLoadedClassesSync())).filter(name => !name.startsWith('[')).sort(); }); }
      catch (e) { javaError = String(e); }
    } else javaError = 'No Java VM';
    return {
      modules: modules.slice(0, 2048).map(m => ({ name: m.name, path: m.path, base: m.base.toString(), size: m.size })),
      classes: classes.slice(0, 30000),
      truncated: modules.length > 2048 || classes.length > 30000,
      javaError,
    };
  },
  members(kind, name) {
    if (kind === 'module') {
      const module = Process.enumerateModules().find(m => m.path === name);
      if (!module) throw new Error('Module is no longer loaded');
      const functions = module.enumerateExports().filter(s => s.type === 'function');
      return { kind, name, members: functions.slice(0, 10000).map(s => s.name), truncated: functions.length > 10000 };
    }
    if (kind !== 'class' || !name || /[!*\/]/.test(name)) throw new Error('Invalid class query');
    if (!Java.available) throw new Error('No Java VM');
    let methods = [];
    Java.performNow(() => {
      for (const group of Java.enumerateMethods(name + '!*/s'))
        for (const klass of group.classes)
          if (klass.name === name) methods.push(...klass.methods);
    });
    methods = Array.from(new Set(methods)).sort();
    return { kind, name, members: methods.slice(0, 3000), truncated: methods.length > 3000 };
  },
  symbols(addresses) {
    return addresses.slice(0, 128).map((address) => {
      const p = ptr(address),
        module = Process.findModuleByAddress(p),
        s = DebugSymbol.fromAddress(p);
      return {
        address,
        module: module ? module.path : '',
        symbol: s.name || '',
        status: module ? 'resolved' : 'unmapped',
      };
    });
  },
  prepare(tid, stream) {
    continuous = !!stream;
    if (Process.arch !== 'x64') throw new Error('Active capture currently requires x86_64');
    targetTid = tid;
    javaStatus = Java.available ? 'Java available' : 'No Java VM';
    // Initialize the bridge before arming, without hooking libc I/O functions.
    if (Java.available)
      Java.performNow(() => {
        Java.backtrace({ limit: 1 });
      });
    Process.setExceptionHandler((d) => {
      if (
        !armed ||
        d.type !== 'breakpoint' ||
        (!continuous && Process.getCurrentThreadId() !== targetTid)
      )
        return false;
      // A syscall-return SIGTRAP has RIP immediately after 0f 05, not after int3.
      try {
        if (d.context.pc.sub(2).readU16() !== 0x050f) return false;
      } catch (e) {
        return false;
      }
      if (!continuous) armed = false;
      const registers = {};
      for (const k of [
        'pc',
        'sp',
        'rax',
        'rbx',
        'rcx',
        'rdx',
        'rsi',
        'rdi',
        'rbp',
        'r8',
        'r9',
        'r10',
        'r11',
        'r12',
        'r13',
        'r14',
        'r15',
      ])
        registers[k] = d.context[k].toString();
      let nativeFrames = [],
        nativeError = '';
      try {
        nativeFrames = Thread.backtrace(d.context, Backtracer.ACCURATE).map((p) => {
          const symbol = DebugSymbol.fromAddress(p), module = Process.findModuleByAddress(p);
          return { address: p.toString(), symbol: symbol.toString(), symbolName: symbol.name || '',
            functionOffset: functionOffset(p, symbol, module),
            module: module ? module.path : '', moduleName: module ? module.name : '' };
        });
      } catch (e) {
        nativeError = String(e);
      }
      let java = { source: 'Exception handler', frames: [] };
      try {
        if (!Java.available) java.error = 'No Java VM';
        else if (Java.vm.tryGetEnv() === null) java.error = 'Target TID has no Java environment';
        else java.frames = Java.backtrace({ limit: 64 }).frames;
      } catch (e) {
        java.error = String(e);
      }
      let stack = null;
      if (continuous)
        try {
          const r = Process.findRangeByAddress(d.context.sp);
          if (r)
            stack = d.context.sp.readByteArray(
              Math.min(4096, r.base.add(r.size).sub(d.context.sp).toUInt32())
            );
        } catch (e) {}
      send(
        {
          type: 'capture',
          tid: Process.getCurrentThreadId(),
          registers,
          nativeFrames,
          nativeError,
          java,
          javaStatus,
        },
        stack
      );
      return true;
    });
    return { javaStatus };
  },
  arm() {
    armed = true;
  },
  stop() {
    armed = false;
  },
};
