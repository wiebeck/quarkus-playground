/*
 * Copyright (c) 2022 Riege Software. All rights reserved.
 * Use is subject to license terms.
 */

package com.riege;

import io.quarkus.runtime.StartupEvent;
import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.DefaultJWTTokenParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.config.JWTAuthContextInfoProvider;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Alternative;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtContext;

@ApplicationScoped
@Alternative
@Priority(1)
public class RiegeB2CJWTCallerPrincipalFactory extends JWTCallerPrincipalFactory {

    @Inject
    JWTAuthContextInfoProvider authContextInfoProvider;

    @ConfigProperty(name = "riege.b2c.domain-prefix")
    String b2cDomainPrefix;

    @ConfigProperty(name = "riege.b2c.tenant-id")
    String b2cTenantId;

    @ConfigProperty(name = "riege.b2c.application.id")
    String b2cAppId;

    private MyJWTAuthContextInfo personalAuthContext;
    private MyJWTAuthContextInfo appAuthContext;

    public void init(@Observes StartupEvent event) {
        personalAuthContext =
            new MyJWTAuthContextInfo(authContextInfoProvider.getContextInfo());
        personalAuthContext.setGroupsPath("rsiRole");
        personalAuthContext.setIssuedBy(
            String.format("https://%s.b2clogin.com/%s/v2.0/", b2cDomainPrefix,
                b2cTenantId));
        personalAuthContext.setPublicKeyLocation(String.format(
            "https://%1$s.b2clogin.com/%1$s.onmicrosoft"
                + ".com/b2c_1a_rsisignin/discovery/v2.0/keys", b2cDomainPrefix));

        appAuthContext = new MyJWTAuthContextInfo(authContextInfoProvider.getContextInfo());
        appAuthContext.setGroupsPath("roles");
        appAuthContext.setIssuedBy(
            String.format("https://login.microsoftonline.com/%s/v2.0", b2cTenantId));
        appAuthContext.setPublicKeyLocation(
            String.format("https://login.microsoftonline.com/%s/discovery/v2.0/keys", b2cTenantId));
        appAuthContext.setExpectedAudience(Set.of(b2cAppId));
    }

    @Override
    public JWTCallerPrincipal parse(String token, JWTAuthContextInfo authContextInfo)
        throws ParseException
    {
        try {
            String claimsJson =
                new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]),
                    StandardCharsets.UTF_8);
            JwtClaims claims = JwtClaims.parse(claimsJson);
            MyJWTAuthContextInfo context = claims.getIssuer().contains("b2clogin")
                ? personalAuthContext
                : appAuthContext;

            JwtContext jwtContext = context.parser.parse(token, context);
            String type = jwtContext.getJoseObjects().get(0).getHeader("typ");
            return new DefaultJWTCallerPrincipal(type, jwtContext.getJwtClaims());
        } catch (InvalidJwtException | MalformedClaimException e) {
            throw new ParseException("Error parsing or validating JWT", e);
        }
    }

    private static class MyJWTAuthContextInfo extends JWTAuthContextInfo {
        private final DefaultJWTTokenParser parser;

        public MyJWTAuthContextInfo(JWTAuthContextInfo orig) {
            super(orig);
            parser = new DefaultJWTTokenParser();
        }
    }
}
