package io.github.socgabrielcardoso.traceguard.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

final class InputFiles {
    private static final Set<String> EXTENSIONS = Set.of("log", "txt", "jsonl", "events", "audit");

    private InputFiles() {
    }

    static List<Path> discover(Path input) throws IOException {
        Path normalized = input.toAbsolutePath().normalize();
        if (!Files.exists(normalized)) {
            throw new IOException("Input does not exist: " + input);
        }
        if (Files.isRegularFile(normalized)) {
            return List.of(normalized);
        }
        if (!Files.isDirectory(normalized)) {
            throw new IOException("Input is not a regular file or directory: " + input);
        }

        try (Stream<Path> paths = Files.walk(normalized)) {
            return paths
                    .filter(Files::isRegularFile)
                    .filter(InputFiles::supported)
                    .sorted()
                    .toList();
        }
    }

    static String display(Path input, Path file) {
        Path normalized = input.toAbsolutePath().normalize();
        if (Files.isDirectory(normalized)) {
            return normalized.relativize(file).toString().replace('\\', '/');
        }
        return file.getFileName().toString();
    }

    private static boolean supported(Path path) {
        String name = path.getFileName().toString();
        int separator = name.lastIndexOf('.');
        if (separator < 0 || separator == name.length() - 1) {
            return true;
        }
        return EXTENSIONS.contains(name.substring(separator + 1).toLowerCase(Locale.ROOT));
    }
}

