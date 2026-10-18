class SafeCommandV3 {
    void execute() throws Exception {
        Runtime.getRuntime().exec("/usr/bin/id");
    }
}
