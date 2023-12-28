import axios from "axios"
import Alpine from "alpinejs"

// axios.interceptors.response.use(res => {
//     return res
// }, err => {
//     return err
// })

Alpine.store("loginform_submit", (email) => {
    let password = ""
    for(const idx of Alpine.store("loginform_password_indices")) {
        const e = document.getElementsByName("pindex" + (idx+1))[0]
        password += e.value
    }

    axios.post("https://localhost/api/login", { email, password }, {
        withCredentials: true,
    }).then(res => {
        Alpine.store("loginform_validation", res.data)
        if (res.status == 200) {
            window.location.replace("https://localhost/main.html")
        }
    }).catch(err => {
        Alpine.store("loginform_validation", err.response.data)
    })
})

Alpine.store("btn_logout", () => {
    axios.get("https://localhost/api/logout", {
        withCredentials: true
    }).then(e => {
        if(e.status == 200) {
            window.location.replace("https://localhost/login.html")
        }
    }).catch(e => {
        window.location.replace("https://localhost/login.html")
    })
})

Alpine.store("registerform_submit", (email, passwd, repeat_passwd) => {
    const form = document.getElementById("registerform")
    if (form != null) {
        if (!form.reportValidity()) { return }
    }
    axios.post("https://localhost/api/register", {
        email, password: passwd, password_repeat: repeat_passwd
    }).then(res => {
        Alpine.store("registerform_validation", res.data)
        if (res.status == 200) {
            window.location.replace("https://localhost/login.html")
        }
    }).catch(err => {
        Alpine.store("registerform_validation", err.response.data)
    })
})
Alpine.store("registerform_validate", (email, passwd, repeat_passwd) => {
    axios.post("https://localhost/api/register/validate", {
        email, password: passwd, password_repeat: repeat_passwd
    }).then(res => {
        Alpine.store("registerform_validation", res.data)
    }).catch(err => {
        Alpine.store("registerform_validation", err.response.data)
    })

    return true;
})
Alpine.store("check_jwt", () => {
    axios.get("https://localhost/api/jwt", {withCredentials: true}).then(res => {
        if(res.status == 200) {
            window.location.replace("https://localhost/main.html")
        }
    }).catch(err => {
    })
})
Alpine.store("get_password_indices", (email) => {
    axios.post("https://localhost/api/login/password_indices", {email}).then(res => {
        if(res.status == 200) {
            Alpine.store("loginform_password_indices", res.data.message.indices)
        }
    }).catch(err => {
        Alpine.store("loginform_validation", err.response.data) 
    })
})
Alpine.store("reset_password_indices_inputs", () => {
    Alpine.store("loginform_password_indices", []);
    for(let i=1; i<17; ++i) {
        let e = document.getElementsByName("pindex" + i)[0]
        if(e) {
            e.value = ""
        }
    }
})
Alpine.store("loginform_password_indices", [])
Alpine.store("registerform_validation", { message: '', result: false })
Alpine.store("loginform_validation", { message: '', result: false })

Alpine.start()