import React, { useEffect, useState } from "react";
import { MainHeader } from "./MainHeader";

export const Projects = (props) => {

    const [value, setValue] = useState('');
    const [theme, setTheme] = useState(props.themeState);
    const [data, setData] = useState([]);

    const render = () => {
        var mounted = true;
        const obj = JSON.parse(localStorage.getItem("access_token"));
        const token = "Bearer " + obj.access_token;
        
        var requestOptions = {
            method: "GET",
            headers: {"Authorization":token},
            redirect: "follow"   
        };
                
        fetch(process.env.API_BASE_URL+"/projects", requestOptions)
                .then(response => response.json())
                .then(fetchData => {
                    if(mounted) {
                        setData(fetchData);   
                    }
                });
        return () => mounted = false;
    }
    
    useEffect(() => {
        render();
    }, [])
    
    const changeTheme =(newTheme) => {
        setTheme(newTheme);
    }

    const onSearch = (searchTerm) => {
        setValue(searchTerm);
        props.onSwitch("EditProject", searchTerm, theme);
        render();
    }

    const deleteButton = (item) => {        
        const obj = JSON.parse(localStorage.getItem('access_token'));
        const token = "Bearer " + obj.access_token;
 
        var requestOptions = {
            method: 'DELETE',
            headers: {
                "Authorization":token
            },
            redirect:"follow"
        };
                
        fetch(process.env.API_BASE_URL+'/projects/'+encodeURIComponent(item.name), requestOptions)
          .then(response => {
            console.log(response);
            render();
          })
          .catch(error => {
            props.onSwitch('Error', error, theme);
          });
    }

    return (
        <div className="background" id={theme}>
            <MainHeader current_theme={theme} switchTheme={changeTheme} onSwitch={(stateName, stateVars, theme) => props.onSwitch(stateName, stateVars, theme)} />
            <table className="editproject" id={theme}> 
                <tbody>
                    <tr>
                        <td><table><tbody><tr>
                            <td><h2 className="editproject">Projects</h2></td>
                            <td><button className="editproject" id="add-project" onClick={() => props.onSwitch('EditProject', 'Untitled', theme)}>+</button></td>
                            <td><input className="editproject" value={value} onChange={(e) => setValue(e.target.value)} type="text" placeholder="Search..."></input></td>
                            <td><button className="editproject" onClick={() => render()}>Refresh</button></td>
                        </tr></tbody></table></td>
                    </tr>
                    <tr>
                        <td>
                        <div className="search-container"> 
                            <div className="dropdown">
                                    {data.filter(item => {
                                        const searchTerm = value.toLowerCase();
                                        const name = item.name.toLowerCase();

                                        return (searchTerm && name.startsWith(searchTerm)) || value === '';
                                    }).map((item) => (
                                        <div className="dropdown-row"  key={item.name}>
                                            <table><tbody><tr>
                                                <td><p>{item.name}</p></td>
                                                <td><button className="editproject" id="green" onClick={()=>onSearch(item.name)}>Edit</button></td>
                                                <td><button className="editproject" id="red" onClick={()=>deleteButton(item)}>Delete</button></td>
                                            </tr></tbody></table>
                                        </div>
                                    ))} 
                            </div> 
                         </div>
                         </td>
                    </tr>
                </tbody>
            </table>
        </div>
    )
}
