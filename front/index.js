import axios from "axios"
import Alpine from "alpinejs"

axios.get("https://localhost/api/5").then(e => {
    Alpine.store("message", {"current": e.data})
})

Alpine.store("btn_loginform_submit", (email, password) => {
    axios.post("https://localhost/api/login", {email, password}, {
        withCredentials: true,
        headers: {"Content-Type": "application/json"},
    }).then(res => {
        console.dir(res)
        console.log(res.data)
        axios.get("https://localhost/api/jwt", {
        withCredentials: true
        }).then(e => {

        })
    })
})
Alpine.store("btn_test", () => {
    axios.get("https://localhost/api/jwt", {
        withCredentials: true
    }).then(e => {
        console.log(e.data)
    })
})
Alpine.store("btn_logout", () => {
    axios.get("https://localhost/api/logout", {
        withCredentials: true
    }).then(e => {
        console.log(e.data)
    })
})
Alpine.start()