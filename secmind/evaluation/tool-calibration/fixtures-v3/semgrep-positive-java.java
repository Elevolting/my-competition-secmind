class CommandEndpointV3 {
    void execute(javax.servlet.http.HttpServletRequest request) {
        String command = request.getParameter("command");
        Runtime.getRuntime().exec(command);
    }
}
