package be.atbash.ee.security.soteria.oauth2;

import com.github.scribejava.core.oauth.OAuth20Service;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@ApplicationScoped
public class HttpSessionUtil {

    public static final String STATE = "State";

    public void storeUserState(HttpServletRequest request, OAuth20Service service, String state) {
        HttpSession httpSession = request.getSession();

        httpSession.setAttribute(OAuth20Service.class.getName(), service);
        httpSession.setAttribute("OriginalRequest", request.getRequestURI());
        httpSession.setAttribute(STATE, state);

    }

    public String getState(HttpServletRequest request) {
        HttpSession httpSession = request.getSession();

        String result = (String) httpSession.getAttribute(STATE);
        httpSession.removeAttribute(STATE);
        return result;
    }
}
