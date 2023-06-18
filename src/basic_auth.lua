local digest = require('digest')

function basicAuthHandler(nextHandler, checkMap)
    return function (req)
        if checkMap ~= nil then
            local authorization = req.headers.authorization
            if not authorization then
                return {
                    status = 401
                }
            end

            local userpass_b64 = authorization:match("Basic%s+(.*)")
            if not userpass_b64 then
                return {
                    status = 401
                }
            end

            local userpass = digest.base64_decode(userpass_b64)
            if not userpass then
                return {
                    status = 401
                }
            end

            local username, password = userpass:match("([^:]*):(.*)")
            if not (username and password) then
                return {
                    headers = { ['content-type'] = 'application/json' },
                    status = 401
                }
            end

            if checkMap[username] ~= password then
                return {
                    status = 401
                }
            end
        end

        return nextHandler(req)
    end
end
