package com.example.plugins

import io.ktor.client.*
import io.ktor.client.engine.apache.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.time.Duration

fun Application.configureAuthentication() {
    log.info("[!] Starting Plugin - Authentication.kt")

    data class UserSession(val token: String)
    data class UserData(
        val id: String,
        val name: String,
        @SerialName("given_name") val givenName: String,
        @SerialName("family_name") val familyName: String?,
        val picture: String,
        val locale: String
    )
    install(Sessions) {
        cookie<UserSession>("user_session") {
            cookie.path = "/"
            cookie.maxAgeInSeconds = Duration.ofDays(1).seconds
        }
        cookie<UserData>("user_data") {
            cookie.path = "/"
            cookie.maxAgeInSeconds = Duration.ofDays(1).seconds
        }
    }
    install(Authentication) {
        oauth("auth-oauth-google") {
            client = HttpClient(Apache)
            urlProvider = { "https://0.0.0.0:8080/callback" }
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "google",
                    authorizeUrl = "https://accounts.google.com/o/oauth2/auth",
                    accessTokenUrl = "https://accounts.google.com/o/oauth2/token",
                    requestMethod = HttpMethod.Post,
                    clientId = "InsertClientIDHere",
                    clientSecret = "InsertClientSecretHere",
                    defaultScopes = listOf("https://www.googleapis.com/auth/userinfo.profile"),
                )
            }

        }
    }
    routing {
        authenticate("auth-oauth-google") {
            get("/login") {
                // Redirects to 'authorizeUrl' automatically
            }

            get("/callback") {
                val principal = call.authentication.principal<OAuthAccessTokenResponse.OAuth2>()
                    ?: error("No principal")
                val json = HttpClient(Apache).get("https://www.googleapis.com/userinfo/v2/me") {
                    header("Authorization", "Bearer ${principal.accessToken}")
                }.bodyAsText()
                val UserDataFromJson = Json.decodeFromString<UserInfo>(json)
                call.sessions.set(UserSession(principal.accessToken))
                call.sessions.set(
                    UserData(
                        UserDataFromJson.id,
                        UserDataFromJson.name,
                        UserDataFromJson.givenName,
                        UserDataFromJson.familyName,
                        UserDataFromJson.picture,
                        UserDataFromJson.locale
                    )
                )
                call.respondRedirect("/profile")
            }
        }
        get("/profile") {
            val UserSession = call.sessions.get<UserSession>()
            val UserData = call.sessions.get<UserData>()
            if (UserSession != null) {
                call.respond("Hi! ${UserData?.name} with ID: ${UserData?.id}")
            } else {
                call.respond(HttpStatusCode.Unauthorized, "Not authenticated")
            }
        }

        get("/logout") {
            call.sessions.clear<UserSession>()
            call.sessions.clear<UserData>()
            call.respondRedirect("/")
        }
    }
}
@Serializable
data class UserInfo(
    val id: String,
    val name: String,
    @SerialName("given_name") val givenName: String,
    @SerialName("family_name") val familyName: String,
    val picture: String,
    val locale: String
)

