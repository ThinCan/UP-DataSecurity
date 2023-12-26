import axios from "axios"
import Alpine from "alpinejs"

// axios.interceptors.response.use(res => {
//     return res
// }, err => {
//     return err
// })

Alpine.store("loginform_submit", (email, password) => {
    axios.post("https://localhost/api/login", {email, password}, {
        withCredentials: true,
    }).then(res => {
        console.dir(res)
        console.log(res.data)
        axios.get("https://localhost/api/jwt", {
        withCredentials: true
        }).then(e => {
            console.log("ERROR", e)
        })
    }).catch(e => {
        console.log("ERROR", e.response)
    })
})

Alpine.store("btn_logout", () => {
    axios.get("https://localhost/api/logout", {
        withCredentials: true
    }).then(e => {
        console.log(e.data)
        if(e.status == 401) {
            console.log("ee")
            window.location.replace("https://localhost/40x.html")
        }
    }).catch(e => {
        console.log(e.response)
        if(e.response.status == 401) {
            console.log("ee")
            window.location.replace("https://localhost/40x.html")
        }
    })
})

Alpine.store("registerform_submit", (email, passwd, repeat_passwd) => {
    const form = document.getElementById("registerform")
    if(form != null) {
        if(!form.reportValidity()) { return }
    }
    Alpine.store("registerform_validate")(email, passwd, repeat_passwd)
})
Alpine.store("registerform_validate", (email, passwd, repeat_passwd) => {
    console.log(email, passwd, repeat_passwd)
    axios.post("https://localhost/api/register", {
        email, password: passwd, password_repeat: repeat_passwd
    }).then(res => {
        if(res.status == 200) {
            Alpine.store("registerform_validation", res.data)
            window.location.replace("https://localhost/login.html")
        } else {
            Alpine.store("registerform_validation", res.response.data)
        }
    }).catch(err => {
        console.log("error: ", err)
    })

    return true;
})
Alpine.store("registerform_validation", {message: '', result: false})
Alpine.store("loginform_validation", {message: '', result: false})

Alpine.start()