package com.ben.sercurity;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class HelloResource {
  @RequestMapping(value = "/hello", method = RequestMethod.GET)
  public String hello() {
    return "Hello World";
  }
}
