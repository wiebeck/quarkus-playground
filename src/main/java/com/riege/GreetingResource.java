package com.riege;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("/")
public class GreetingResource {

    @Inject
    JsonWebToken jwt;

    private void printJWTDetails() {
        System.out.println("Issuer: " + jwt.getIssuer());
        System.out.println("Audiences: " + jwt.getAudience());
        System.out.println("Groups: " + jwt.getGroups());
    }

    @GET
    @Path("/all")
    @Produces(MediaType.TEXT_PLAIN)
    public String hello(@Context JWTAuthContextInfo jwtAuthContextInfo) {
        printJWTDetails();
        return "Hello from RESTEasy Reactive";
    }

    @GET
    @Path("/super")
    @RolesAllowed({"RSI_Super_Administrator"})
    @Produces(MediaType.TEXT_PLAIN)
    public String superAdmin(@Context JWTAuthContextInfo jwtAuthContextInfo) {
        printJWTDetails();
        return "Hello RSI_Super_Admin";
    }

    @GET
    @Path("/agent")
    @RolesAllowed({"agent-service.writer"})
    @Produces(MediaType.TEXT_PLAIN)
    public String agent(@Context JWTAuthContextInfo jwtAuthContextInfo) {
        printJWTDetails();
        return "Hello agent-service.writer";
    }
}
