package io.github.socgabrielcardoso.traceguard.domain;

public record FileDigest(String path, long bytes, String sha256) {
}
