import jakarta.servlet.http.HttpServletRequest;
import java.lang.Runtime;

final class SemgrepPositiveJava {
    void run(HttpServletRequest request) {
        String command = request.getParameter("command");
        Runtime.getRuntime().exec(command);
    }
}
