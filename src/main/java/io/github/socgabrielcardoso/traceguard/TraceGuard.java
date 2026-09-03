package io.github.socgabrielcardoso.traceguard;

import io.github.socgabrielcardoso.traceguard.cli.TraceGuardApp;

public final class TraceGuard {
    private TraceGuard() {
    }

    public static void main(String[] arguments) {
        int exitCode = new TraceGuardApp(System.out, System.err).run(arguments);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }
}
