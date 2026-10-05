// Headless Ghidra post-script: decompile the functions containing the given
// addresses to C, and for each write one line
//     <entry_hex>\t<base64(C text)>\t<base64(JSON per-line address array)>
// The address array has one entry per line of the C text ("0x...." or null),
// so the report can map a machine address to the exact pseudo-code line and show
// a focused window of the decompiled function per graph node.
// Invoked by vexhound's report generator when --ghidra-home is provided.
// Args: <out_file> <comma-separated hex addresses>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;

public class DecompFuncs extends GhidraScript {
    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: DecompFuncs <out_file> <hex,hex,...>");
            return;
        }
        String outPath = args[0];
        String[] addrs = args.length > 1 ? args[1].split(",") : new String[0];

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        PrintWriter w = new PrintWriter(outPath);
        HashSet<Long> done = new HashSet<>();
        for (String h : addrs) {
            if (h == null || h.isEmpty()) continue;
            Address ad = toAddr(Long.decode(h).longValue());   // Long.decode handles 0x...
            Function fn = fm.getFunctionContaining(ad);
            if (fn == null) continue;
            long entry = fn.getEntryPoint().getOffset();
            if (!done.add(entry)) continue;
            DecompileResults r = di.decompileFunction(fn, 60, monitor);
            if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) continue;

            // Build the text and the per-line address map from the SAME line list,
            // so line i of the text corresponds to entry i of the address array.
            String text;
            String addrJson;
            try {
                List<ClangLine> lines = DecompilerUtils.toLines(r.getCCodeMarkup());
                StringBuilder tb = new StringBuilder();
                StringBuilder ab = new StringBuilder("[");
                for (int i = 0; i < lines.size(); i++) {
                    ClangLine ln = lines.get(i);
                    if (i > 0) { tb.append("\n"); ab.append(","); }
                    tb.append(ln.toString());
                    Address best = null;
                    for (ClangToken t : ln.getAllTokens()) {
                        Address ta = t.getMinAddress();
                        if (ta != null && (best == null || ta.getOffset() < best.getOffset())) best = ta;
                    }
                    ab.append(best == null ? "null"
                              : ("\"0x" + Long.toHexString(best.getOffset()) + "\""));
                }
                ab.append("]");
                text = tb.toString();
                addrJson = ab.toString();
            } catch (Throwable e) {
                // Fall back to the plain C with no line map if the markup API differs.
                text = r.getDecompiledFunction().getC();
                addrJson = "[]";
            }
            w.println("0x" + Long.toHexString(entry) + "\t" + b64(text) + "\t" + b64(addrJson));
        }
        w.close();
        println("WROTE " + outPath);
    }
}
