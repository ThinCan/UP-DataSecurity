import axios from "axios"
import Alpine from "alpinejs"

// axios.interceptors.response.use(res => {
//     return res
// }, err => {
//     return err
// })

Alpine.store("loginform_submit", (email) => {
    let password = ""
    for (const idx of Alpine.store("loginform_password_indices")) {
        const e = document.getElementsByName("pindex" + (idx + 1))[0]
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
    }).finally(() => {
        Alpine.store("login_gettries")()
    })
})

Alpine.store("btn_logout", () => {
    axios.get("https://localhost/api/logout", {
        withCredentials: true
    }).then(e => {
        if (e.status == 200) {
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
    axios.get("https://localhost/api/jwt", { withCredentials: true }).then(res => {
        if (res.status == 200 && window.location.toString() != "https://localhost/main.html") {
            window.location.replace("https://localhost/main.html")
        }
    }).catch(err => {
        if (err.response.status == 401 && window.location.toString() != "https://localhost/login.html") {
            window.location.replace("https://localhost/login.html")
        }
    })
})
Alpine.store("get_password_indices", (email) => {
    axios.post("https://localhost/api/login/password_indices", { email }).then(res => {
        if (res.status == 200) {
            Alpine.store("loginform_password_indices", res.data.message.indices)
        }
    }).catch(err => {
        Alpine.store("loginform_validation", err.response.data)
    })
})
Alpine.store("reset_password_indices_inputs", () => {
    Alpine.store("loginform_password_indices", []);
    for (let i = 1; i < 17; ++i) {
        let e = document.getElementsByName("pindex" + i)[0]
        if (e) {
            e.value = ""
        }
    }
})
Alpine.store("transferform_transfer", (to, amount, title, address) => {
    console.log(to, amount, title, address)
    axios.post("https://localhost/api/transfer/make", {
        to, amount, title, address
    }, { withCredentials: true }).then(res => {
        if (res.status == 200) {
            const new_balance = res.data.new_balance
            Alpine.store("transferform_validation", res.data)
            Alpine.store("transfer_balance", new_balance)
            Alpine.store("transfer_gethistory")()
        }
    }).catch(err => {
        console.log(err.response.data)
        Alpine.store("transferform_validation", err.response.data)
    })
})

Alpine.store("transfer_getbalance", () => {
    axios.get("https://localhost/api/transfer/balance", { withCredentials: true })
        .then(res => {
            if (res.status == 200) {
                console.log("ASD")
                Alpine.store("transfer_balance", res.data.message.balance)
            }
        }).catch(err => {
            if (err.status == 401) {
                let message = err.response.data.msg + ". Try loggin in again"
                console.log(message)
                Alpine.store("transferform_validation", { message, result: false })
            }
        })
})

Alpine.store("transfer_getaccount", () => {
    axios.get("https://localhost/api/transfer/account_number", { withCredentials: true })
        .then(res => {
            if (res.status == 200) {
                Alpine.store("transfer_account", res.data.message.account.toString())
            }
        }).catch(err => { })
})

Alpine.store("transfer_gethistory", () => {
    axios.get("https://localhost/api/transfer/history", { withCredentials: true })
        .then(res => {
            if (res.status == 200) {
                let transfers = res.data.message.history
                Alpine.store("transfer_history", transfers)
            }
        }).catch(err => { })
})
Alpine.store("login_gettries", () => {
    axios.get("https://localhost/api/login/tries").then(res => {
        if (res.status == 200) {
            console.log(res)
            Alpine.store("login_logintries", 5 - res.data.message.attempt)
        }
    }).catch(err => { })
})
Alpine.store("loginform_change_password", (email) => {
    axios.post("https://localhost/api/change_password", {email}).then(res => {
        if(res.status == 200) {
            window.location.assign("https://localhost/password_reset.html")
        }
    }).catch(err => {
        if(err.response.status == 401 || !!err.response.data.message) {
            Alpine.store("loginform_validation", err.response.data)
        }
    })
})
Alpine.store("passwordchangeform_submit", (secret, password, password_repeat) => {
    axios.post("https://localhost/api/change_password", {secret, password, password_repeat}).then(res => {
        if(res.status == 200) {
            window.location.assign("https://localhost/login.html")
        }
    }).catch(err => {
        if(err.response.status == 401 || !!err.response.data.message) {
            Alpine.store("passwordchangeform_validation", err.response.data)
        }
    })
})

Alpine.store("loginform_password_indices", [])
Alpine.store("login_logintries", 5)
Alpine.store("loginform_validation", { message: '', result: false })
Alpine.store("registerform_validation", { message: '', result: false })
Alpine.store("transferform_validation", { message: '', result: false })
Alpine.store("transfer_history", [])
Alpine.store("passwordchangeform_validation", { message: '', result: false })

Alpine.start()