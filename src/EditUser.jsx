import React, { useEffect, useState } from "react";
import { MainHeader } from "./MainHeader";

export const EditUser = (props) => {
  
  const [theme, setTheme] = useState(props.themeState);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('No defaults provided');
  
  const render = () => {
        var mounted = true;
        const obj = JSON.parse(localStorage.getItem("access_token"));
        const token = "Bearer " + obj.access_token;
        
        var requestOptions = {
            method: "GET",
            headers: {
                "Authorization":token
            },
            redirect: "follow"   
        };
                
        console.log(props.stateVars);
        if(props.stateVars === "Untitled") {
          setUsername("Untitled"); 
        } else {
          fetch(process.env.API_BASE_URL+"/users/"+encodeURIComponent(props.stateVars), requestOptions)
                  .then(response => response.json())
                  .then(fetchData => {
                      if(mounted) {
                          setUsername(fetchData.username);
                          setPassword(fetchData.password);
                      }
                  });
        }
        return () => mounted = false;
  }
  
  useEffect(() => {
    render();
  }, [])
    
  const changeTheme =(newTheme) => {
    setTheme(newTheme);
  }
  
  const saveRecord = () => {
    /* api call goes here */ 
    console.log(username);
    console.log(password);
    
    if(props.stateVars === 'Untitled') {
        const obj = JSON.parse(localStorage.getItem("access_token"));
        const token = "Bearer " + obj.access_token;
      
        var raw = {
          "username":username,
          "password":password
        };
        
        var requestOptions = {
            method: "POST",
            headers: {
              "Authorization":token,
              "Content-Type":"application/json"
            },
            body: JSON.stringify(raw),
            redirect: "follow"   
        };
      
         fetch(process.env.API_BASE_URL+'/users', requestOptions)
            .then(response => {
                response.json()
            })
            .then(data => {
                console.log(data)
            })
      
    } else {
      console.log('edit');
    }
    props.onSwitch('Admin', '', theme);
    render();
  }
  
  return (
    <div className="background" id={theme}>
      <MainHeader current_theme={theme} switchTheme={changeTheme} onSwitch={(stateName, stateVars, theme) => props.onSwitch(stateName, stateVars, theme)} />
      <table>
        <tbody>
          <tr>
            <td><h2 className="editrecord">Current user: {props.stateVars}</h2></td>
          </tr>
          <tr>
            <td><p>Username: </p></td>
            <td><p>Password: </p></td>
          </tr>
          <tr> 
              <td><input className="editrecord" type="text" placeholder={username} onChange={(e) => setUsername(e.target.value)}></input></td>
              <td><input className="editrecord" type="text" placeholder={password} onChange={(e) => setPassword(e.target.value)}></input></td>
              <td><button className="editrecord" onClick={() => saveRecord()}>Save</button></td>
          </tr>
          <tr>
              <td><button className="editrecord" onClick={() => props.onSwitch('Admin', '', theme)}>"Return without saving"</button></td>
          </tr>
        </tbody>
      </table>
    </div>
  )
  
}
