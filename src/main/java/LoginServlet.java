import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@WebServlet(
        description = "Login Servlet Testing",
        urlPatterns = { "/LoginServlet"},
        initParams = {
            @WebInitParam(name = "user" , value = "Mohan"),
            @WebInitParam(name = "password", value = "Bridgelabz9@")
        }
)
public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String user = request.getParameter("user");
        String namePattern = "^[A-Z]{1}[a-z]{3,}$";                                                     //Applying Regex Pattern for name
        Pattern pattern = Pattern.compile(namePattern);
        Matcher match = pattern.matcher(user);

        String pwd = request.getParameter("pwd");

        String pass = "^(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&-+=()]).{8,}$";               //applying Regex pattern for password
        Pattern pattern2 = Pattern.compile(pass);
        Matcher match2 = pattern2.matcher(pwd);

        String userID = getServletConfig().getInitParameter("user");
        String password = getServletConfig().getInitParameter("password");
        if (pattern.matcher(user).matches() && userID.equals(user) && password.equals(pwd) && pattern2.matcher(pwd).matches()) {        //verifying username and password matches according to regex
            request.setAttribute("user", user);
            request.getRequestDispatcher("LoginSuccess.jsp").forward(request, response);
        } else {
            RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
            PrintWriter out = response.getWriter();
            out.println("<font colour=red> User Name or password is incorrect");
            rd.include(request, response);
        }

    }
}
