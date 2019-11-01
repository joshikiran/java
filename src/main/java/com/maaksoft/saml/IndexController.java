package com.maaksoft.saml;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {

	@RequestMapping("/matrices")
	@ResponseBody
	public Response testMatrices() throws Exception {
		Response res = new Response();
		res.setStatus("OK");
		res.setStatusDescription("Successful in fetching user information");
		return res;
	}

	@RequestMapping({"/user", "/saml/metadata"})
	@ResponseBody
	public Response login(Principal user) throws Exception {
		Response res = new Response();
		res.setStatus("OK");
		res.setStatusDescription("Successful in fetching user information");
		return res;
	}
	
	@PostMapping("/saml/SSO")
	@ResponseBody
	public Response doSomething(Principal user) throws Exception {
		Response res = new Response();
		res.setStatus("OK");
		res.setStatusDescription("Successful in fetching user information");
		return res;
	}
	
	
}

class Response {
	String status;
	String statusDescription;

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getStatusDescription() {
		return statusDescription;
	}

	public void setStatusDescription(String statusDescription) {
		this.statusDescription = statusDescription;
	}

}