final class SemgrepNegativeJava {
    void run() throws Exception {
        new ProcessBuilder("/usr/bin/true").start();
    }
}
