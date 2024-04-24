# Certificate Authority
## Introduction
This project implements an API for  Certificate Authority.
## Structure:
1. logs: This folder contains the log directory. Not much is implemented as standard log/slog package is used as the logger for this project. The log package can be configured to send logs from a certain log level to elasticsearch.
2. db: This handles the database operations. This database uses MySQL to store data. You **MUST UPDATE** the db.yaml to with the database details. These are the default details:
    ```yaml
        db: "ca"
        user: "root"
        password: "123456"
    ```
3. REST API:
    #### a. Authentication:
    The authentication happens through signin and signup handlers. The signup works through redirect. It redirects to the casdoor and Casdoor redirects back to the handlers. Once the signup or signin happens, the user is saved in Casdoor and MySQL database for the CA returns Auth token.
    Example of response JSON to signin and signup:
    ```json
        {
            "data":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImNlcnQtYnVpbHQtaW4iLCJ0eXAiOiJKV1QifQ.eyJvd25lciI6ImJ1aWx0LWluIiwibmFtZSI6Im13YXVyYXdha2F0aSIsImNyZWF0ZWRUaW1lIjoiMjAyNC0wNC0xMVQyMTowODo0NSswMzowMCIsInVwZGF0ZWRUaW1lIjoiMjAyNC0wNC0xMVQyMToxMzo1NyswMzowMCIsImRlbGV0ZWRUaW1lIjoiIiwiaWQiOiI4NTQzMjM5NyIsInR5cGUiOiJub3JtYWwtdXNlciIsInBhc3N3b3JkIjoiIiwicGFzc3dvcmRTYWx0IjoiIiwicGFzc3dvcmRUeXBlIjoicGxhaW4iLCJkaXNwbGF5TmFtZSI6Ik13YXVyYSBXYWthdGkiLCJmaXJzdE5hbWUiOiIiLCJsYXN0TmFtZSI6IiIsImF2YXRhciI6Imh0dHBzOi8vYXZhdGFycy5naXRodWJ1c2VyY29udGVudC5jb20vdS84NTQzMjM5Nz92PTQiLCJhdmF0YXJUeXBlIjoiIiwicGVybWFuZW50QXZhdGFyIjoiIiwiZW1haWwiOiJtd2F1cmF3YWthdGlAZ21haWwuY29tIiwiZW1haWxWZXJpZmllZCI6ZmFsc2UsInBob25lIjoiIiwiY291bnRyeUNvZGUiOiIiLCJyZWdpb24iOiIiLCJsb2NhdGlvbiI6IiIsImFkZHJlc3MiOltdLCJhZmZpbGlhdGlvbiI6IiIsInRpdGxlIjoiIiwiaWRDYXJkVHlwZSI6IiIsImlkQ2FyZCI6IiIsImhvbWVwYWdlIjoiIiwiYmlvIjoiIiwibGFuZ3VhZ2UiOiIiLCJnZW5kZXIiOiIiLCJiaXJ0aGRheSI6IiIsImVkdWNhdGlvbiI6IiIsInNjb3JlIjoyMDAwLCJrYXJtYSI6MCwicmFua2luZyI6MTIsImlzRGVmYXVsdEF2YXRhciI6ZmFsc2UsImlzT25saW5lIjpmYWxzZSwiaXNBZG1pbiI6ZmFsc2UsImlzRm9yYmlkZGVuIjpmYWxzZSwiaXNEZWxldGVkIjpmYWxzZSwic2lnbnVwQXBwbGljYXRpb24iOiJDQSIsImhhc2giOiIiLCJwcmVIYXNoIjoiIiwiYWNjZXNzS2V5IjoiIiwiYWNjZXNzU2VjcmV0IjoiIiwiZ2l0aHViIjoiODU0MzIzOTciLCJnb29nbGUiOiIiLCJxcSI6IiIsIndlY2hhdCI6IiIsImZhY2Vib29rIjoiIiwiZGluZ3RhbGsiOiIiLCJ3ZWlibyI6IiIsImdpdGVlIjoiIiwibGlua2VkaW4iOiIiLCJ3ZWNvbSI6IiIsImxhcmsiOiIiLCJnaXRsYWIiOiIiLCJjcmVhdGVkSXAiOiIiLCJsYXN0U2lnbmluVGltZSI6IiIsImxhc3RTaWduaW5JcCI6IiIsInByZWZlcnJlZE1mYVR5cGUiOiIiLCJyZWNvdmVyeUNvZGVzIjpudWxsLCJ0b3RwU2VjcmV0IjoiIiwibWZhUGhvbmVFbmFibGVkIjpmYWxzZSwibWZhRW1haWxFbmFibGVkIjpmYWxzZSwibGRhcCI6IiIsInByb3BlcnRpZXMiOnsibm8iOiIxMyIsIm9hdXRoX0dpdEh1Yl9hdmF0YXJVcmwiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvODU0MzIzOTc_dj00Iiwib2F1dGhfR2l0SHViX2Rpc3BsYXlOYW1lIjoiTXdhdXJhIFdha2F0aSIsIm9hdXRoX0dpdEh1Yl9lbWFpbCI6Im13YXVyYXdha2F0aUBnbWFpbC5jb20iLCJvYXV0aF9HaXRIdWJfaWQiOiI4NTQzMjM5NyIsIm9hdXRoX0dpdEh1Yl91c2VybmFtZSI6Im13YXVyYXdha2F0aSJ9LCJyb2xlcyI6W10sInBlcm1pc3Npb25zIjpbXSwiZ3JvdXBzIjpbXSwibGFzdFNpZ25pbldyb25nVGltZSI6IiIsInNpZ25pbldyb25nVGltZXMiOjAsInRva2VuVHlwZSI6ImFjY2Vzcy10b2tlbiIsInRhZyI6IiIsInNjb3BlIjoicmVhZCIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsInN1YiI6Ijg1NDMyMzk3IiwiYXVkIjpbIjE3MWU3ODZiYzA3M2RmNWQ3NWQxIl0sImV4cCI6MTcxMzQ2NDAzNywibmJmIjoxNzEyODU5MjM3LCJpYXQiOjE3MTI4NTkyMzcsImp0aSI6ImFkbWluL2NhNTliZDdkLWE3NjctNDY4Ny1iYzg3LTYyYWZjYzE3Yzk0OCJ9.eLOsBp6ewJQGA3Mk7aNrBy1h6AYw9BCGEf0DJXM3bVREaaup47YScw1fcwCT3ozytKbtcWLymAtacBZ9k-ddxTv9ed1Sk74I1zMwqcqa2-xAD605W-diurR_w8VQaLsXsahqmmo_vxgy0VNeE9x7RMLTxURJIAr9jNO2jGnFzrjlotuDn1EWSKZXduicdLtEFoWVooedz4It2ujH9_eKIUOy2OszAzxHmDiJU9tZiN9lYuuy_g6AaR54TweXndjwcvtIU9Si4w46BavVbOfM1lGHPUNsmD4mRSJEWOeJ6BctHS6gmdkccA3lsJimtkZGu5DUrPNxSXy1PHTFEFYlDkvgYnLORAS7C3dcBEXXS-3wLk_prszERoPCGuRB4ASfJRozzOYTP8xev6Sb6zsbLnp1nAQs8H66CqdTj4hFewWLTmSix_SWWpZhi9SIXf1po0c7i0mx9IguYWUeOWRmUodkYmsZ7shLvvdLKV8JawEQvNdzcUc2o0WScFA_CKWBiF6sOouFtHO0xE21u7hgXA58ta4vWGkzMI218WQDnfDOtVqbxtzEcIdDIFK-1JnyfPRp06m9mmBip04mbQchlQCpsfXs6LEYdweqA4ULJYpvkpkS6pm7Hgo1S1VtnRy-S8DxfntxnVCuiRCY82jjQRtq6NrnVI4nFmkr9BoFjEw",
            "status":"ok"
        }
    ```
    Except for signin and signup all the other endpoints needs to have Authentication header 
    #### b. Get User
    ```go
        package main

        import (
        "fmt"
        "net/http"
        "io/ioutil"
        )

        func main() {

        url := "localhost:8080/api/v1/users/mwaurawakati"
        method := "GET"

        client := &http.Client {
        }
        req, err := http.NewRequest(method, url, nil)

        if err != nil {
            fmt.Println(err)
            return
        }
        req.Header.Add("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImNlcnQtYnVpbHQtaW4iLCJ0eXAiOiJKV1QifQ.eyJvd25lciI6ImJ1aWx0LWluIiwibmFtZSI6Im13YXVyYXdha2F0aSIsImNyZWF0ZWRUaW1lIjoiMjAyNC0wNC0xMVQyMTowODo0NSswMzowMCIsInVwZGF0ZWRUaW1lIjoiMjAyNC0wNC0xMlQxMjowOToxMyswMzowMCIsImRlbGV0ZWRUaW1lIjoiIiwiaWQiOiI4NTQzMjM5NyIsInR5cGUiOiJub3JtYWwtdXNlciIsInBhc3N3b3JkIjoiIiwicGFzc3dvcmRTYWx0IjoiIiwicGFzc3dvcmRUeXBlIjoicGxhaW4iLCJkaXNwbGF5TmFtZSI6Ik13YXVyYSBXYWthdGkiLCJmaXJzdE5hbWUiOiIiLCJsYXN0TmFtZSI6IiIsImF2YXRhciI6Imh0dHBzOi8vYXZhdGFycy5naXRodWJ1c2VyY29udGVudC5jb20vdS84NTQzMjM5Nz92PTQiLCJhdmF0YXJUeXBlIjoiIiwicGVybWFuZW50QXZhdGFyIjoiIiwiZW1haWwiOiJtd2F1cmF3YWthdGlAZ21haWwuY29tIiwiZW1haWxWZXJpZmllZCI6ZmFsc2UsInBob25lIjoiIiwiY291bnRyeUNvZGUiOiIiLCJyZWdpb24iOiIiLCJsb2NhdGlvbiI6IiIsImFkZHJlc3MiOltdLCJhZmZpbGlhdGlvbiI6IiIsInRpdGxlIjoiIiwiaWRDYXJkVHlwZSI6IiIsImlkQ2FyZCI6IiIsImhvbWVwYWdlIjoiIiwiYmlvIjoiIiwibGFuZ3VhZ2UiOiIiLCJnZW5kZXIiOiIiLCJiaXJ0aGRheSI6IiIsImVkdWNhdGlvbiI6IiIsInNjb3JlIjoyMDAwLCJrYXJtYSI6MCwicmFua2luZyI6MTIsImlzRGVmYXVsdEF2YXRhciI6ZmFsc2UsImlzT25saW5lIjpmYWxzZSwiaXNBZG1pbiI6ZmFsc2UsImlzRm9yYmlkZGVuIjpmYWxzZSwiaXNEZWxldGVkIjpmYWxzZSwic2lnbnVwQXBwbGljYXRpb24iOiJDQSIsImhhc2giOiIiLCJwcmVIYXNoIjoiIiwiYWNjZXNzS2V5IjoiIiwiYWNjZXNzU2VjcmV0IjoiIiwiZ2l0aHViIjoiODU0MzIzOTciLCJnb29nbGUiOiIiLCJxcSI6IiIsIndlY2hhdCI6IiIsImZhY2Vib29rIjoiIiwiZGluZ3RhbGsiOiIiLCJ3ZWlibyI6IiIsImdpdGVlIjoiIiwibGlua2VkaW4iOiIiLCJ3ZWNvbSI6IiIsImxhcmsiOiIiLCJnaXRsYWIiOiIiLCJjcmVhdGVkSXAiOiIiLCJsYXN0U2lnbmluVGltZSI6IiIsImxhc3RTaWduaW5JcCI6IiIsInByZWZlcnJlZE1mYVR5cGUiOiIiLCJyZWNvdmVyeUNvZGVzIjpudWxsLCJ0b3RwU2VjcmV0IjoiIiwibWZhUGhvbmVFbmFibGVkIjpmYWxzZSwibWZhRW1haWxFbmFibGVkIjpmYWxzZSwibGRhcCI6IiIsInByb3BlcnRpZXMiOnsibm8iOiIxMyIsIm9hdXRoX0dpdEh1Yl9hdmF0YXJVcmwiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvODU0MzIzOTc_dj00Iiwib2F1dGhfR2l0SHViX2Rpc3BsYXlOYW1lIjoiTXdhdXJhIFdha2F0aSIsIm9hdXRoX0dpdEh1Yl9lbWFpbCI6Im13YXVyYXdha2F0aUBnbWFpbC5jb20iLCJvYXV0aF9HaXRIdWJfaWQiOiI4NTQzMjM5NyIsIm9hdXRoX0dpdEh1Yl91c2VybmFtZSI6Im13YXVyYXdha2F0aSJ9LCJyb2xlcyI6W10sInBlcm1pc3Npb25zIjpbXSwiZ3JvdXBzIjpbXSwibGFzdFNpZ25pbldyb25nVGltZSI6IiIsInNpZ25pbldyb25nVGltZXMiOjAsInRva2VuVHlwZSI6ImFjY2Vzcy10b2tlbiIsInRhZyI6IiIsInNjb3BlIjoicmVhZCIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsInN1YiI6Ijg1NDMyMzk3IiwiYXVkIjpbIjE3MWU3ODZiYzA3M2RmNWQ3NWQxIl0sImV4cCI6MTcxMzUxNzc1MywibmJmIjoxNzEyOTEyOTUzLCJpYXQiOjE3MTI5MTI5NTMsImp0aSI6ImFkbWluL2JmMGJlYjhlLTUwNDUtNDQzNC05NTc1LWY4YjQ4OWU0MDc2NSJ9.px1_npyMJ-2hSFJapGCk_3VMk6CZJRXqCGbWfQvxKA4v64pKulprJi9whM9olnA7rgEIoAECVhF6a1ZRy_3iVnb5vPQ_rdsofmcsqFXZ2MsMHjlicUVbXvOGiqd6ojBc0FBrjXO3pTvh5usAACyP33pyol0nyhjGeft6rjmfopAXw2sRUMj9OW1JEXexOjZjZCpTQpPuaGU1FlU5trS9yiMBZzXESo5P5Fbt90LlT9jm4qqI2L23fL5Uj08PMSodbaMGz_QzeLsiJZN6IBTCBzRD_0_g5brsYVwDlyP6C7Kr5497SbE71YlW04E3VmQv_u6tqyo09cL6e-CFzpIpLttOhrwKaWHruEjEkGFTveJ7gK6yZi9fr7NEoBClh_AU1tCPza0r253HIYtCQkrOhJEBmExDRnHAa-d0QQOSPEXmFEtMugSShWUH8gTTA22QNJZSMY_YUrcABu7WpsCyiUm9UlfVyxO45PqFYwaTvLdYXhyQDS1ULHVWnbPOMe9dStlpimMeZNMaj-q7H32e-aIFfykFKDfLRc72ibVi0SGYFjCBwJbJQBjxVrLaZZ2ibx-gPamMcpOCG7XqMPbnf69G_YKduMuEEo4kqJ5YeRGrv8t4Lncxl0tNmR93jl3OyXfuEg1fbE4g34-qXsXXdQBmDFy49hBK8R6dLWKh_z0")

        res, err := client.Do(req)
        if err != nil {
            fmt.Println(err)
            return
        }
        defer res.Body.Close()

        body, err := ioutil.ReadAll(res.Body)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println(string(body))
        }
    ```
    The example above gets a given user and gives the following json response when successful
    ```json
        {
            "data": {
                "ID": 6,
                "CreatedAt": "2024-04-11T21:03:00.532+03:00",
                "UpdatedAt": "2024-04-11T21:03:00.532+03:00",
                "DeletedAt": null,
                "owner": "built-in",
                "name": "mwaurawakati",
                "createdTime": "",
                "updatedTime": "",
                "idd": "85432397",
                "type": "normal-user",
                "password": "",
                "passwordSalt": "",
                "passwordType": "plain",
                "displayName": "Mwaura Wakati",
                "firstName": "",
                "lastName": "",
                "avatar": "https://avatars.githubusercontent.com/u/85432397?v=4",
                "avatarType": "",
                "permanentAvatar": "",
                "email": "mwaurawakati@gmail.com",
                "emailVerified": false,
                "phone": "",
                "countryCode": "",
                "region": "",
                "location": "",
                "affiliation": "",
                "title": "",
                "idCardType": "",
                "idCard": "",
                "homepage": "",
                "bio": "",
                "tag": "",
                "language": "",
                "gender": "",
                "birthday": "",
                "education": "",
                "score": 2000,
                "karma": 0,
                "ranking": 12,
                "isDefaultAvatar": false,
                "isOnline": false,
                "isAdmin": false,
                "isForbidden": false,
                "isDeleted": false,
                "signupApplication": "CA",
                "hash": "",
                "preHash": "",
                "accessKey": "",
                "accessSecret": "",
                "createdIp": "",
                "lastSigninTime": "",
                "lastSigninIp": "",
                "github": "85432397",
                "google": "",
                "qq": "",
                "wechat": "",
                "facebook": "",
                "dingtalk": "",
                "weibo": "",
                "gitee": "",
                "linkedin": "",
                "wecom": "",
                "lark": "",
                "gitlab": "",
                "adfs": "",
                "baidu": "",
                "alipay": "",
                "casdoor": "",
                "infoflow": "",
                "apple": "",
                "azuread": "",
                "slack": "",
                "steam": "",
                "bilibili": "",
                "okta": "",
                "douyin": "",
                "line": "",
                "amazon": "",
                "auth0": "",
                "battlenet": "",
                "bitbucket": "",
                "box": "",
                "cloudfoundry": "",
                "dailymotion": "",
                "deezer": "",
                "digitalocean": "",
                "discord": "",
                "dropbox": "",
                "eveonline": "",
                "fitbit": "",
                "gitea": "",
                "heroku": "",
                "influxcloud": "",
                "instagram": "",
                "intercom": "",
                "kakao": "",
                "lastfm": "",
                "mailru": "",
                "meetup": "",
                "microsoftonline": "",
                "naver": "",
                "nextcloud": "",
                "onedrive": "",
                "oura": "",
                "patreon": "",
                "paypal": "",
                "salesforce": "",
                "shopify": "",
                "soundcloud": "",
                "spotify": "",
                "strava": "",
                "stripe": "",
                "tiktok": "",
                "tumblr": "",
                "twitch": "",
                "twitter": "",
                "typetalk": "",
                "uber": "",
                "vk": "",
                "wepay": "",
                "xero": "",
                "yahoo": "",
                "yammer": "",
                "yandex": "",
                "zoom": "",
                "metamask": "",
                "web3onboard": "",
                "custom": ""
            },
            "status": "ok"
        }
    ```
    If the auth token is not present, you get the following error
    ```json
        {
            "error": 400,
            "message": "Wrong or absent Authentication key"
        }
    ```
    User not found response
    ```json
        {
            "error": {},
            "message": "User not found"
        }
    ```
    #### c: Delete User
    Example script
    ```go
        package main

        import (
        "fmt"
        "net/http"
        "io/ioutil"
        )

        func main() {

        url := "localhost:8080/api/v1/users/mwaurawakat"
        method := "DELETE"

        client := &http.Client {
        }
        req, err := http.NewRequest(method, url, nil)

        if err != nil {
            fmt.Println(err)
            return
        }
        req.Header.Add("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImNlcnQtYnVpbHQtaW4iLCJ0eXAiOiJKV1QifQ.eyJvd25lciI6ImJ1aWx0LWluIiwibmFtZSI6Im13YXVyYXdha2F0aSIsImNyZWF0ZWRUaW1lIjoiMjAyNC0wNC0xMVQyMTowODo0NSswMzowMCIsInVwZGF0ZWRUaW1lIjoiMjAyNC0wNC0xMlQxMjowOToxMyswMzowMCIsImRlbGV0ZWRUaW1lIjoiIiwiaWQiOiI4NTQzMjM5NyIsInR5cGUiOiJub3JtYWwtdXNlciIsInBhc3N3b3JkIjoiIiwicGFzc3dvcmRTYWx0IjoiIiwicGFzc3dvcmRUeXBlIjoicGxhaW4iLCJkaXNwbGF5TmFtZSI6Ik13YXVyYSBXYWthdGkiLCJmaXJzdE5hbWUiOiIiLCJsYXN0TmFtZSI6IiIsImF2YXRhciI6Imh0dHBzOi8vYXZhdGFycy5naXRodWJ1c2VyY29udGVudC5jb20vdS84NTQzMjM5Nz92PTQiLCJhdmF0YXJUeXBlIjoiIiwicGVybWFuZW50QXZhdGFyIjoiIiwiZW1haWwiOiJtd2F1cmF3YWthdGlAZ21haWwuY29tIiwiZW1haWxWZXJpZmllZCI6ZmFsc2UsInBob25lIjoiIiwiY291bnRyeUNvZGUiOiIiLCJyZWdpb24iOiIiLCJsb2NhdGlvbiI6IiIsImFkZHJlc3MiOltdLCJhZmZpbGlhdGlvbiI6IiIsInRpdGxlIjoiIiwiaWRDYXJkVHlwZSI6IiIsImlkQ2FyZCI6IiIsImhvbWVwYWdlIjoiIiwiYmlvIjoiIiwibGFuZ3VhZ2UiOiIiLCJnZW5kZXIiOiIiLCJiaXJ0aGRheSI6IiIsImVkdWNhdGlvbiI6IiIsInNjb3JlIjoyMDAwLCJrYXJtYSI6MCwicmFua2luZyI6MTIsImlzRGVmYXVsdEF2YXRhciI6ZmFsc2UsImlzT25saW5lIjpmYWxzZSwiaXNBZG1pbiI6ZmFsc2UsImlzRm9yYmlkZGVuIjpmYWxzZSwiaXNEZWxldGVkIjpmYWxzZSwic2lnbnVwQXBwbGljYXRpb24iOiJDQSIsImhhc2giOiIiLCJwcmVIYXNoIjoiIiwiYWNjZXNzS2V5IjoiIiwiYWNjZXNzU2VjcmV0IjoiIiwiZ2l0aHViIjoiODU0MzIzOTciLCJnb29nbGUiOiIiLCJxcSI6IiIsIndlY2hhdCI6IiIsImZhY2Vib29rIjoiIiwiZGluZ3RhbGsiOiIiLCJ3ZWlibyI6IiIsImdpdGVlIjoiIiwibGlua2VkaW4iOiIiLCJ3ZWNvbSI6IiIsImxhcmsiOiIiLCJnaXRsYWIiOiIiLCJjcmVhdGVkSXAiOiIiLCJsYXN0U2lnbmluVGltZSI6IiIsImxhc3RTaWduaW5JcCI6IiIsInByZWZlcnJlZE1mYVR5cGUiOiIiLCJyZWNvdmVyeUNvZGVzIjpudWxsLCJ0b3RwU2VjcmV0IjoiIiwibWZhUGhvbmVFbmFibGVkIjpmYWxzZSwibWZhRW1haWxFbmFibGVkIjpmYWxzZSwibGRhcCI6IiIsInByb3BlcnRpZXMiOnsibm8iOiIxMyIsIm9hdXRoX0dpdEh1Yl9hdmF0YXJVcmwiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvODU0MzIzOTc_dj00Iiwib2F1dGhfR2l0SHViX2Rpc3BsYXlOYW1lIjoiTXdhdXJhIFdha2F0aSIsIm9hdXRoX0dpdEh1Yl9lbWFpbCI6Im13YXVyYXdha2F0aUBnbWFpbC5jb20iLCJvYXV0aF9HaXRIdWJfaWQiOiI4NTQzMjM5NyIsIm9hdXRoX0dpdEh1Yl91c2VybmFtZSI6Im13YXVyYXdha2F0aSJ9LCJyb2xlcyI6W10sInBlcm1pc3Npb25zIjpbXSwiZ3JvdXBzIjpbXSwibGFzdFNpZ25pbldyb25nVGltZSI6IiIsInNpZ25pbldyb25nVGltZXMiOjAsInRva2VuVHlwZSI6ImFjY2Vzcy10b2tlbiIsInRhZyI6IiIsInNjb3BlIjoicmVhZCIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsInN1YiI6Ijg1NDMyMzk3IiwiYXVkIjpbIjE3MWU3ODZiYzA3M2RmNWQ3NWQxIl0sImV4cCI6MTcxMzUxNzc1MywibmJmIjoxNzEyOTEyOTUzLCJpYXQiOjE3MTI5MTI5NTMsImp0aSI6ImFkbWluL2JmMGJlYjhlLTUwNDUtNDQzNC05NTc1LWY4YjQ4OWU0MDc2NSJ9.px1_npyMJ-2hSFJapGCk_3VMk6CZJRXqCGbWfQvxKA4v64pKulprJi9whM9olnA7rgEIoAECVhF6a1ZRy_3iVnb5vPQ_rdsofmcsqFXZ2MsMHjlicUVbXvOGiqd6ojBc0FBrjXO3pTvh5usAACyP33pyol0nyhjGeft6rjmfopAXw2sRUMj9OW1JEXexOjZjZCpTQpPuaGU1FlU5trS9yiMBZzXESo5P5Fbt90LlT9jm4qqI2L23fL5Uj08PMSodbaMGz_QzeLsiJZN6IBTCBzRD_0_g5brsYVwDlyP6C7Kr5497SbE71YlW04E3VmQv_u6tqyo09cL6e-CFzpIpLttOhrwKaWHruEjEkGFTveJ7gK6yZi9fr7NEoBClh_AU1tCPza0r253HIYtCQkrOhJEBmExDRnHAa-d0QQOSPEXmFEtMugSShWUH8gTTA22QNJZSMY_YUrcABu7WpsCyiUm9UlfVyxO45PqFYwaTvLdYXhyQDS1ULHVWnbPOMe9dStlpimMeZNMaj-q7H32e-aIFfykFKDfLRc72ibVi0SGYFjCBwJbJQBjxVrLaZZ2ibx-gPamMcpOCG7XqMPbnf69G_YKduMuEEo4kqJ5YeRGrv8t4Lncxl0tNmR93jl3OyXfuEg1fbE4g34-qXsXXdQBmDFy49hBK8R6dLWKh_z0")

        res, err := client.Do(req)
        if err != nil {
            fmt.Println(err)
            return
        }
        defer res.Body.Close()

        body, err := ioutil.ReadAll(res.Body)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println(string(body))
        }
    ```
    Example resposes:
    Succeess:
    ```json
        {
            "message": "User deleted unsuccessfully"
        }
    ```
    Failure(User not exist)
    ```json
        {
            "message": "User deleted unsuccessfully"
        }
    ```


# CERTIFICATE AUTHORITY
## Supported Algorithms
1. [RSA](https://pkg.go.dev/crypto/rsa@go1.22.2)
2. [ED25519](https://pkg.go.dev/crypto/ed25519@go1.22.2#PrivateKey)
3. [ECDSA](https://pkg.go.dev/crypto/ecdsa@go1.22.2)

These three algorithms implement [Signer](https://pkg.go.dev/crypto#Signer) struct of the [crypto](https://pkg.go.dev/crypto) standard library. This project utilizes [x509](https://pkg.go.dev/crypto/x509@go1.22.2) standard library for certificate creation


## The endpoints
These endpoints have not been authenticated but they can be easily authenticated through a middleware

| Method        | Endpoint      | Exaplnation |
| ------------- |-------------| -----|
| GET           | /api/v1/ca    | List all certificate authority certificates |
| POST          | /api/v1/ca      |   Create a CA certificate |
| GET           | /api/v1/ca/:cn      |    Get a given CA certificate  |
| GET           | /api/v1/ca/:cn/certificates | Get a list of certificates belonging to a given CA |
| POST          | /api/v1/ca/:cn/certificates | Issue a certificate from the CA                    |
| GET           | /api/v1/ca/:cn/certificates/:cert_cn | Get an issued certficate using cn CA certificate where cert_cn is the common name|
| DELETE        | /api/v1/ca/:cn/certificates/:cert_cn | Revoke a certificate. Add a certificate to the list of revoked certificates                            |


**NOTE**
The Certificate algorithm must match the algroithm of the CA

## Creating a CA certificate
### The payload
```json
    {
        "common_name":"g",
        "parent_common_name":"a",
        "identity":{
            "organization":"test",
            "organization_unit":"test",
            "country":"KE",
            "locality":"Nyeri",
            "province":"Central",
            "algorithm":"ecdsa",
            "intermediate": false

        }
    }
```
### Sample response response
```json
    {
    "Data": {
        "common_name": "f",
        "intermediate": false,
        "status": "Certificate Authority is ready.",
        "serial_number": "206252863373477999951052358965596148275",
        "issue_date": "2024-04-14 08:58:24 +0000 UTC",
        "expire_date": "2025-05-16 08:58:24 +0000 UTC",
        "dns_names": [
            "f"
        ],
        "csr": false,
        "certificates": [],
        "revoked_certificates": null,
        "files": {
            "crl": "-----BEGIN X509 CRL-----\nMIIBZjCByAIBATAKBggqhkjOPQQDBDBZMQswCQYDVQQGEwJLRTEQMA4GA1UECBMH\nQ2VudHJhbDEOMAwGA1UEBxMFTnllcmkxDTALBgNVBAoTBHRlc3QxDTALBgNVBAsT\nBHRlc3QxCjAIBgNVBAMTAWYXDTI0MDQxNDA4NTgyNFoXDTI0MDQxNTA4NTgyNFqg\nPjA8MB8GA1UdIwQYMBaAFJkNI9HNTvZcVfR+Ufg0FZtv/iqLMBkGA1UdFAQSAhBi\njr1CtSaOcCVEffRSeKEyMAoGCCqGSM49BAMEA4GMADCBiAJCAZ4A+HfwUIupFJAr\nYjT+KWCxz/1mvW/0+wdkX8TpKlY6Bw/NLzYKM44WoOkXhqUpZ+OibGziFwmhc8Uy\n1GBRTeOEAkIA2OMOhWAOs7z1CAcpyzUcefAgxWCfWJMOjL/d7ONAjYahrHEwYnpS\nN8BJb0+1YKoGlYOU993MCeaau+Q2Oqt3aoo=\n-----END X509 CRL-----\n",
            "certificate": "-----BEGIN CERTIFICATE-----\nMIICpzCCAgmgAwIBAgIRAJsq20gVaXVByQItpwUGUjMwCgYIKoZIzj0EAwQwWTEL\nMAkGA1UEBhMCS0UxEDAOBgNVBAgTB0NlbnRyYWwxDjAMBgNVBAcTBU55ZXJpMQ0w\nCwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MQowCAYDVQQDEwFmMB4XDTI0MDQx\nNDA4NTgyNFoXDTI1MDUxNjA4NTgyNFowWTELMAkGA1UEBhMCS0UxEDAOBgNVBAgT\nB0NlbnRyYWwxDjAMBgNVBAcTBU55ZXJpMQ0wCwYDVQQKEwR0ZXN0MQ0wCwYDVQQL\nEwR0ZXN0MQowCAYDVQQDEwFmMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBpmCU\n+gfL+6dlgS9aTMn3semgQM/GTCUmu6ma82UO8R0mS/D6m6Ghu1cFxGTDFh014mV3\ntsY2p4vYsCjwA0SlQLIBmT02FzP+yg1qJ11hdeUi2BKMLDjm950EFG5BosppwEp6\nQZChIoTusHNyF/Rwu6zsYaXOmkcb4UhvDrGMFRjxn8ajbzBtMA4GA1UdDwEB/wQE\nAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw\nAwEB/zAdBgNVHQ4EFgQUmQ0j0c1O9lxV9H5R+DQVm2/+KoswDAYDVR0RBAUwA4IB\nZjAKBggqhkjOPQQDBAOBiwAwgYcCQWmw55WYfN8ggK4pSJCiuYwCSSEFwFN1pmIs\nyIUIa9E4f2pheUQ5q5ZUqHjRjusSnWufEoC263TBHruruHSixap6AkIBH8UhtMr2\nUFLByQc0rcsUusJQ5CCr209mWbx9UYxYHRoOKVh0YrEa68YLJlWv6M/spM0SG8r0\nJMPKy3xzwGTxcyM=\n-----END CERTIFICATE-----\n",
            "csr": "",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBfrLjSDj4TLU6cWdZ\n853W2FmsAT1uonz5RipTGCL+i6VdeyneNq+v4ZhFCYsEqr1HwWBYte40eXm35Ek/\nOboORQuhgYkDgYYABAGmYJT6B8v7p2WBL1pMyfex6aBAz8ZMJSa7qZrzZQ7xHSZL\n8PqboaG7VwXEZMMWHTXiZXe2xjani9iwKPADRKVAsgGZPTYXM/7KDWonXWF15SLY\nEowsOOb3nQQUbkGiymnASnpBkKEihO6wc3IX9HC7rOxhpc6aRxvhSG8OsYwVGPGf\nxg==\n-----END PRIVATE KEY-----\n",
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBpmCU+gfL+6dlgS9aTMn3semgQM/G\nTCUmu6ma82UO8R0mS/D6m6Ghu1cFxGTDFh014mV3tsY2p4vYsCjwA0SlQLIBmT02\nFzP+yg1qJ11hdeUi2BKMLDjm950EFG5BosppwEp6QZChIoTusHNyF/Rwu6zsYaXO\nmkcb4UhvDrGMFRjxn8Y=\n-----END PUBLIC KEY-----\n",
            "Privatekey": {
                "Curve": {},
                "X": 5663153353088874385673697699778221048576789283380633323687784962757058783783520911241664639094385342705263612328128969909416518679416518934645998195327713458,
                "Y": 5486999338816302122470973205118747247753454146392464249422044125600357496658151014553185468932790994352335908298608499388293706759689657506672709608903122886,
                "D": 5131151744636524876659116962523941347769114151683214791638292619124719999531604639394750377496533792205836997742377103750716837173018602952306892096561628427
            },
            "Ccertificate": {
                "Raw": "MIICpzCCAgmgAwIBAgIRAJsq20gVaXVByQItpwUGUjMwCgYIKoZIzj0EAwQwWTELMAkGA1UEBhMCS0UxEDAOBgNVBAgTB0NlbnRyYWwxDjAMBgNVBAcTBU55ZXJpMQ0wCwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MQowCAYDVQQDEwFmMB4XDTI0MDQxNDA4NTgyNFoXDTI1MDUxNjA4NTgyNFowWTELMAkGA1UEBhMCS0UxEDAOBgNVBAgTB0NlbnRyYWwxDjAMBgNVBAcTBU55ZXJpMQ0wCwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MQowCAYDVQQDEwFmMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBpmCU+gfL+6dlgS9aTMn3semgQM/GTCUmu6ma82UO8R0mS/D6m6Ghu1cFxGTDFh014mV3tsY2p4vYsCjwA0SlQLIBmT02FzP+yg1qJ11hdeUi2BKMLDjm950EFG5BosppwEp6QZChIoTusHNyF/Rwu6zsYaXOmkcb4UhvDrGMFRjxn8ajbzBtMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUmQ0j0c1O9lxV9H5R+DQVm2/+KoswDAYDVR0RBAUwA4IBZjAKBggqhkjOPQQDBAOBiwAwgYcCQWmw55WYfN8ggK4pSJCiuYwCSSEFwFN1pmIsyIUIa9E4f2pheUQ5q5ZUqHjRjusSnWufEoC263TBHruruHSixap6AkIBH8UhtMr2UFLByQc0rcsUusJQ5CCr209mWbx9UYxYHRoOKVh0YrEa68YLJlWv6M/spM0SG8r0JMPKy3xzwGTxcyM=",
                "RawTBSCertificate": "MIICCaADAgECAhEAmyrbSBVpdUHJAi2nBQZSMzAKBggqhkjOPQQDBDBZMQswCQYDVQQGEwJLRTEQMA4GA1UECBMHQ2VudHJhbDEOMAwGA1UEBxMFTnllcmkxDTALBgNVBAoTBHRlc3QxDTALBgNVBAsTBHRlc3QxCjAIBgNVBAMTAWYwHhcNMjQwNDE0MDg1ODI0WhcNMjUwNTE2MDg1ODI0WjBZMQswCQYDVQQGEwJLRTEQMA4GA1UECBMHQ2VudHJhbDEOMAwGA1UEBxMFTnllcmkxDTALBgNVBAoTBHRlc3QxDTALBgNVBAsTBHRlc3QxCjAIBgNVBAMTAWYwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAGmYJT6B8v7p2WBL1pMyfex6aBAz8ZMJSa7qZrzZQ7xHSZL8PqboaG7VwXEZMMWHTXiZXe2xjani9iwKPADRKVAsgGZPTYXM/7KDWonXWF15SLYEowsOOb3nQQUbkGiymnASnpBkKEihO6wc3IX9HC7rOxhpc6aRxvhSG8OsYwVGPGfxqNvMG0wDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSZDSPRzU72XFX0flH4NBWbb/4qizAMBgNVHREEBTADggFm",
                "RawSubjectPublicKeyInfo": "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBpmCU+gfL+6dlgS9aTMn3semgQM/GTCUmu6ma82UO8R0mS/D6m6Ghu1cFxGTDFh014mV3tsY2p4vYsCjwA0SlQLIBmT02FzP+yg1qJ11hdeUi2BKMLDjm950EFG5BosppwEp6QZChIoTusHNyF/Rwu6zsYaXOmkcb4UhvDrGMFRjxn8Y=",
                "RawSubject": "MFkxCzAJBgNVBAYTAktFMRAwDgYDVQQIEwdDZW50cmFsMQ4wDAYDVQQHEwVOeWVyaTENMAsGA1UEChMEdGVzdDENMAsGA1UECxMEdGVzdDEKMAgGA1UEAxMBZg==",
                "RawIssuer": "MFkxCzAJBgNVBAYTAktFMRAwDgYDVQQIEwdDZW50cmFsMQ4wDAYDVQQHEwVOeWVyaTENMAsGA1UEChMEdGVzdDENMAsGA1UECxMEdGVzdDEKMAgGA1UEAxMBZg==",
                "Signature": "MIGHAkFpsOeVmHzfIICuKUiQormMAkkhBcBTdaZiLMiFCGvROH9qYXlEOauWVKh40Y7rEp1rnxKAtut0wR67q7h0osWqegJCAR/FIbTK9lBSwckHNK3LFLrCUOQgq9tPZlm8fVGMWB0aDilYdGKxGuvGCyZVr+jP7KTNEhvK9CTDyst8c8Bk8XMj",
                "SignatureAlgorithm": 12,
                "PublicKeyAlgorithm": 3,
                "PublicKey": {
                    "Curve": {},
                    "X": 5663153353088874385673697699778221048576789283380633323687784962757058783783520911241664639094385342705263612328128969909416518679416518934645998195327713458,
                    "Y": 5486999338816302122470973205118747247753454146392464249422044125600357496658151014553185468932790994352335908298608499388293706759689657506672709608903122886
                },
                "Version": 3,
                "SerialNumber": 206252863373477999951052358965596148275,
                "Issuer": {
                    "Country": [
                        "KE"
                    ],
                    "Organization": [
                        "test"
                    ],
                    "OrganizationalUnit": [
                        "test"
                    ],
                    "Locality": [
                        "Nyeri"
                    ],
                    "Province": [
                        "Central"
                    ],
                    "StreetAddress": null,
                    "PostalCode": null,
                    "SerialNumber": "",
                    "CommonName": "f",
                    "Names": [
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                6
                            ],
                            "Value": "KE"
                        },
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                8
                            ],
                            "Value": "Central"
                        },
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                7
                            ],
                            "Value": "Nyeri"
                        },
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                10
                            ],
                            "Value": "test"
                        },
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                11
                            ],
                            "Value": "test"
                        },
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                3
                            ],
                            "Value": "f"
                        }
                    ],
                    "ExtraNames": null
                },
                "Subject": {
                    "Country": [
                        "KE"
                    ],
                    "Organization": [
                        "test"
                    ],
                    "OrganizationalUnit": [
                        "test"
                    ],
                    "Locality": [
                        "Nyeri"
                    ],
                    "Province": [
                        "Central"
                    ],
                    "StreetAddress": null,
                    "PostalCode": null,
                    "SerialNumber": "",
                    "CommonName": "f",
                    "Names": [
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                6
                            ],
                            "Value": "KE"
                        },
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                8
                            ],
                            "Value": "Central"
                        },
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                7
                            ],
                            "Value": "Nyeri"
                        },
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                10
                            ],
                            "Value": "test"
                        },
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                11
                            ],
                            "Value": "test"
                        },
                        {
                            "Type": [
                                2,
                                5,
                                4,
                                3
                            ],
                            "Value": "f"
                        }
                    ],
                    "ExtraNames": null
                },
                "NotBefore": "2024-04-14T08:58:24Z",
                "NotAfter": "2025-05-16T08:58:24Z",
                "KeyUsage": 97,
                "Extensions": [
                    {
                        "Id": [
                            2,
                            5,
                            29,
                            15
                        ],
                        "Critical": true,
                        "Value": "AwIBhg=="
                    },
                    {
                        "Id": [
                            2,
                            5,
                            29,
                            37
                        ],
                        "Critical": false,
                        "Value": "MBQGCCsGAQUFBwMCBggrBgEFBQcDAQ=="
                    },
                    {
                        "Id": [
                            2,
                            5,
                            29,
                            19
                        ],
                        "Critical": true,
                        "Value": "MAMBAf8="
                    },
                    {
                        "Id": [
                            2,
                            5,
                            29,
                            14
                        ],
                        "Critical": false,
                        "Value": "BBSZDSPRzU72XFX0flH4NBWbb/4qiw=="
                    },
                    {
                        "Id": [
                            2,
                            5,
                            29,
                            17
                        ],
                        "Critical": false,
                        "Value": "MAOCAWY="
                    }
                ],
                "ExtraExtensions": null,
                "UnhandledCriticalExtensions": null,
                "ExtKeyUsage": [
                    2,
                    1
                ],
                "UnknownExtKeyUsage": null,
                "BasicConstraintsValid": true,
                "IsCA": true,
                "MaxPathLen": -1,
                "MaxPathLenZero": false,
                "SubjectKeyId": "mQ0j0c1O9lxV9H5R+DQVm2/+Kos=",
                "AuthorityKeyId": null,
                "OCSPServer": null,
                "IssuingCertificateURL": null,
                "DNSNames": [
                    "f"
                ],
                "EmailAddresses": null,
                "IPAddresses": null,
                "URIs": null,
                "PermittedDNSDomainsCritical": false,
                "PermittedDNSDomains": null,
                "ExcludedDNSDomains": null,
                "PermittedIPRanges": null,
                "ExcludedIPRanges": null,
                "PermittedEmailAddresses": null,
                "ExcludedEmailAddresses": null,
                "PermittedURIDomains": null,
                "ExcludedURIDomains": null,
                "CRLDistributionPoints": null,
                "PolicyIdentifiers": null,
                "Policies": null
            },
            "Publickey": {
                "Curve": {},
                "X": 5663153353088874385673697699778221048576789283380633323687784962757058783783520911241664639094385342705263612328128969909416518679416518934645998195327713458,
                "Y": 5486999338816302122470973205118747247753454146392464249422044125600357496658151014553185468932790994352335908298608499388293706759689657506672709608903122886
            },
            "Csr": null,
            "Crl": null,
            "IsIntermediate": false
        }
    }
}
```
### Sample error response
```json
{
    "error": "a Certificate Authority with this common name already exists"
}
```
### Example Golang creation of the endpoint
```go
package main

import (
  "fmt"
  "strings"
  "net/http"
  "io/ioutil"
)

func main() {

  url := "localhost:8080/api/v1/ca"
  method := "POST"

  payload := strings.NewReader(`{
    "common_name":"f",
    "parent_common_name":"a",
    "identity":{
        "organization":"test",
        "organization_unit":"test",
        "country":"KE",
        "locality":"Nyeri",
        "province":"Central",
        "algorithm":"ecdsa",
        "intermediate": false

    }
}`)

  client := &http.Client {
  }
  req, err := http.NewRequest(method, url, payload)

  if err != nil {
    fmt.Println(err)
    return
  }
  req.Header.Add("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImNlcnQtYnVpbHQtaW4iLCJ0eXAiOiJKV1QifQ.eyJvd25lciI6ImJ1aWx0LWluIiwibmFtZSI6Im13YXVyYXdha2F0aSIsImNyZWF0ZWRUaW1lIjoiMjAyNC0wNC0xMVQyMTowODo0NSswMzowMCIsInVwZGF0ZWRUaW1lIjoiMjAyNC0wNC0xMlQxMjowOToxMyswMzowMCIsImRlbGV0ZWRUaW1lIjoiIiwiaWQiOiI4NTQzMjM5NyIsInR5cGUiOiJub3JtYWwtdXNlciIsInBhc3N3b3JkIjoiIiwicGFzc3dvcmRTYWx0IjoiIiwicGFzc3dvcmRUeXBlIjoicGxhaW4iLCJkaXNwbGF5TmFtZSI6Ik13YXVyYSBXYWthdGkiLCJmaXJzdE5hbWUiOiIiLCJsYXN0TmFtZSI6IiIsImF2YXRhciI6Imh0dHBzOi8vYXZhdGFycy5naXRodWJ1c2VyY29udGVudC5jb20vdS84NTQzMjM5Nz92PTQiLCJhdmF0YXJUeXBlIjoiIiwicGVybWFuZW50QXZhdGFyIjoiIiwiZW1haWwiOiJtd2F1cmF3YWthdGlAZ21haWwuY29tIiwiZW1haWxWZXJpZmllZCI6ZmFsc2UsInBob25lIjoiIiwiY291bnRyeUNvZGUiOiIiLCJyZWdpb24iOiIiLCJsb2NhdGlvbiI6IiIsImFkZHJlc3MiOltdLCJhZmZpbGlhdGlvbiI6IiIsInRpdGxlIjoiIiwiaWRDYXJkVHlwZSI6IiIsImlkQ2FyZCI6IiIsImhvbWVwYWdlIjoiIiwiYmlvIjoiIiwibGFuZ3VhZ2UiOiIiLCJnZW5kZXIiOiIiLCJiaXJ0aGRheSI6IiIsImVkdWNhdGlvbiI6IiIsInNjb3JlIjoyMDAwLCJrYXJtYSI6MCwicmFua2luZyI6MTIsImlzRGVmYXVsdEF2YXRhciI6ZmFsc2UsImlzT25saW5lIjpmYWxzZSwiaXNBZG1pbiI6ZmFsc2UsImlzRm9yYmlkZGVuIjpmYWxzZSwiaXNEZWxldGVkIjpmYWxzZSwic2lnbnVwQXBwbGljYXRpb24iOiJDQSIsImhhc2giOiIiLCJwcmVIYXNoIjoiIiwiYWNjZXNzS2V5IjoiIiwiYWNjZXNzU2VjcmV0IjoiIiwiZ2l0aHViIjoiODU0MzIzOTciLCJnb29nbGUiOiIiLCJxcSI6IiIsIndlY2hhdCI6IiIsImZhY2Vib29rIjoiIiwiZGluZ3RhbGsiOiIiLCJ3ZWlibyI6IiIsImdpdGVlIjoiIiwibGlua2VkaW4iOiIiLCJ3ZWNvbSI6IiIsImxhcmsiOiIiLCJnaXRsYWIiOiIiLCJjcmVhdGVkSXAiOiIiLCJsYXN0U2lnbmluVGltZSI6IiIsImxhc3RTaWduaW5JcCI6IiIsInByZWZlcnJlZE1mYVR5cGUiOiIiLCJyZWNvdmVyeUNvZGVzIjpudWxsLCJ0b3RwU2VjcmV0IjoiIiwibWZhUGhvbmVFbmFibGVkIjpmYWxzZSwibWZhRW1haWxFbmFibGVkIjpmYWxzZSwibGRhcCI6IiIsInByb3BlcnRpZXMiOnsibm8iOiIxMyIsIm9hdXRoX0dpdEh1Yl9hdmF0YXJVcmwiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvODU0MzIzOTc_dj00Iiwib2F1dGhfR2l0SHViX2Rpc3BsYXlOYW1lIjoiTXdhdXJhIFdha2F0aSIsIm9hdXRoX0dpdEh1Yl9lbWFpbCI6Im13YXVyYXdha2F0aUBnbWFpbC5jb20iLCJvYXV0aF9HaXRIdWJfaWQiOiI4NTQzMjM5NyIsIm9hdXRoX0dpdEh1Yl91c2VybmFtZSI6Im13YXVyYXdha2F0aSJ9LCJyb2xlcyI6W10sInBlcm1pc3Npb25zIjpbXSwiZ3JvdXBzIjpbXSwibGFzdFNpZ25pbldyb25nVGltZSI6IiIsInNpZ25pbldyb25nVGltZXMiOjAsInRva2VuVHlwZSI6ImFjY2Vzcy10b2tlbiIsInRhZyI6IiIsInNjb3BlIjoicmVhZCIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsInN1YiI6Ijg1NDMyMzk3IiwiYXVkIjpbIjE3MWU3ODZiYzA3M2RmNWQ3NWQxIl0sImV4cCI6MTcxMzUxNzc1MywibmJmIjoxNzEyOTEyOTUzLCJpYXQiOjE3MTI5MTI5NTMsImp0aSI6ImFkbWluL2JmMGJlYjhlLTUwNDUtNDQzNC05NTc1LWY4YjQ4OWU0MDc2NSJ9.px1_npyMJ-2hSFJapGCk_3VMk6CZJRXqCGbWfQvxKA4v64pKulprJi9whM9olnA7rgEIoAECVhF6a1ZRy_3iVnb5vPQ_rdsofmcsqFXZ2MsMHjlicUVbXvOGiqd6ojBc0FBrjXO3pTvh5usAACyP33pyol0nyhjGeft6rjmfopAXw2sRUMj9OW1JEXexOjZjZCpTQpPuaGU1FlU5trS9yiMBZzXESo5P5Fbt90LlT9jm4qqI2L23fL5Uj08PMSodbaMGz_QzeLsiJZN6IBTCBzRD_0_g5brsYVwDlyP6C7Kr5497SbE71YlW04E3VmQv_u6tqyo09cL6e-CFzpIpLttOhrwKaWHruEjEkGFTveJ7gK6yZi9fr7NEoBClh_AU1tCPza0r253HIYtCQkrOhJEBmExDRnHAa-d0QQOSPEXmFEtMugSShWUH8gTTA22QNJZSMY_YUrcABu7WpsCyiUm9UlfVyxO45PqFYwaTvLdYXhyQDS1ULHVWnbPOMe9dStlpimMeZNMaj-q7H32e-aIFfykFKDfLRc72ibVi0SGYFjCBwJbJQBjxVrLaZZ2ibx-gPamMcpOCG7XqMPbnf69G_YKduMuEEo4kqJ5YeRGrv8t4Lncxl0tNmR93jl3OyXfuEg1fbE4g34-qXsXXdQBmDFy49hBK8R6dLWKh_z0")
  req.Header.Add("Content-Type", "text/plain")

  res, err := client.Do(req)
  if err != nil {
    fmt.Println(err)
    return
  }
  defer res.Body.Close()

  body, err := ioutil.ReadAll(res.Body)
  if err != nil {
    fmt.Println(err)
    return
  }
  fmt.Println(string(body))
}
```

## Creating a server/client certficate
Specify the type of the certficate in the payload

```json
    {
        "common_name":"g",
        "parent_common_name":"a",
        "identity":{
            "organization":"test",
            "organization_unit":"test",
            "country":"KE",
            "locality":"Nyeri",
            "province":"Central",
            "algorithm":"ecdsa",
            "intermediate": false,
            "cert_type":"client" // Or "cert_type":"server"

        }
    }
```

The algorithm of the certificate **MUST** match that of the CA certificate else will result in an error


