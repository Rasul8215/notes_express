const express=require("express")
const Database=require("./db")
const database=new Database()
const fs=require("fs")
const bcrypt=require("bcrypt")
const jwt=require("jsonwebtoken")
const app=express()
app.use(express.json())

const secret="hello"
const file='users.json'
const adduser=(username,password)=>{
  const user=JSON.parse(
    fs.readFileSync(file,{encoding:"utf-8"}) || "{}"
  )
  user[username]={username,password}
  fs.writeFileSync(file,JSON.stringify(user))
}
const getuser=(username)=>{
    const user=JSON.parse(
      fs.readFileSync(file,{encoding:'utf-8'}) || "{}"
    )
    return user[username]
  }


  app.post("/note",(req,res)=>{
    const data=req.body
    if (!("title" in data) || !("note" in data) || !("privacy" in data) || !("username" in data)){
        res.status(400).send("title,note,privacy and username is mandatory")
        return
    }
    database.create("notes",{
        "title":data.title,
        "note":data.title,
        "username":data.username,
        "privacy":data.privacy
    })
    res.send("success")
})


app.post("/signup",(req,res)=>{
    const data=req.body
    if (!("username" in data) || !("password" in data)){
        res.status(400).send("username and password is mandatory")
        return
    }
    if ((data.password.length) < 7){
        res.status(403).send("password not strong")
    }
    if (getuser(data.username)){
        res.status(400).send("please signin")
    }
    const hashpass=bcrypt.hashSync(data.password,10)
    adduser(data.username,hashpass)
    res.send("signup sucessfull")
})
app.post("/signin",(req,res)=>{
    const data=req.body
    if (!("username" in data) || !("password" in data)){
        res.status(400).send("username and password is mandatory")
        return
    }
    const user=getuser(data.username)
    if (!(user)){
        res.status(404).send("wrong user")
    }
    if (!(bcrypt.compareSync(data.password,user.password))){
        res.status(403).send("password wrong")
    }
    const token=jwt.sign(data,secret)
    res.send(token)
})
app.use((req, res, next) => {
    const { authorization } = req.headers;
    const jwttoken = authorization.replace("Bearer ", "").trim();
    if (!jwttoken) {
      res.sendStatus(401);
      return;
    }
  
    jwt.verify(jwttoken, secret, (err, data) => {
      if (err) {
        res.status(403).send("JWT Invalid");
        return;
      }
  
      req.user = data;
      next();
    });
  });

app.get("/notes",(req,res)=>{
    const notes=database.read("notes")
    res.json(notes.filter((note)=>{
        if (req.user.username===notes.username || note.privacy==="public"){
            return true
        }
    }))
})
app.get("/note/:id", (req, res) => {
    const id=req.params.idd
    const notes=database.read("notes",id)
    if (!(req.user.username===notes.username) && !(req.user.privacy==="private")){
        res.status(403).send("your unable to read")
    }
    res.json(notes);
  });


app.put("/note/:id",(req,res)=>{
    const id=req.params.id
    const data=req.body
    if (!("title" in data) && !("note" in data)){
        res.send(400).json("title and note is mandatory")
        return
    }
    database.update("notes",id,{...data})
    res.send("success")
})

app.delete("/note/:id",(req,res)=>{
    const id =req.params.id
    database.delete("notes",id)
    res.send("sucess")
})




app.listen(3001)