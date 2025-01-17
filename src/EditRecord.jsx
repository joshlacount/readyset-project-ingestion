import React, { useEffect, useState } from "react";
import { MainHeader } from "./MainHeader";
export const EditRecord = (props) => {

    const [theme, setTheme] = useState(props.themeState);
        /* Form variables for sending to db*/    
    const [project_name, setProjectName] = useState('');
    const [add_height, setAddHeight] = useState('');
    const [add_info, setAddInfo] = useState('');
    const [amount_measurement, setAmountMeasurement] = useState('');
    const [amount_unit, setAmountUnit] = useState('');
    const [count_num, setCountNum] = useState('');
    const [count_unit, setCountUnit] = useState('');
    const [depth, setDepth] = useState('');
    const [drc_upc, setDrcUpc] = useState('');
    const [height, setHeight] = useState('');
    const [name, setName] = useState('');
    const [template_name, setTemplateName] = useState('');
    const [upc, setUpc] = useState('');
    const [width, setWidth] = useState('');
        /* Template variables to populate the '?' fields */
    const [donor_shape, set_donor_shape] = useState('');
    const [form_desc, set_form_desc] = useState('');
    const [gltf, set_gltf] = useState('');
    const [notes, set_notes] = useState('');
    const [product_upc, set_product_upc] = useState('');
    const [type, set_type] = useState('');
    const [workflow, set_workflow] = useState('');
        /* Inferred Hooks */
    const [drc, set_drc] = useState('');
    const [new_template_checkbox, set_new_template_checkbox] = useState('');
    
    useEffect(() => {
        var mounted = true;
        
        const obj = JSON.parse(localStorage.getItem("access_token"));
        const token = "Bearer " + obj.access_token;
        var requestOptions = {
            method: "GET",
            headers: {
                "Authorization":token,
            },
            redirect: "follow"
        };
        if(props.stateVars === "new record") {
            clearRecord(); 
        } else {
            const str = process.env.API_BASE_URL+'/products/'+encodeURIComponent(props.stateVars);
            fetch(str, requestOptions)
              .then(response => response.json())
              .then(fetchData => {
                    console.log(fetchData)
                    if(mounted) {
                        setAddHeight(fetchData.add_height);
                        setAddInfo(fetchData.add_info);
                        setAmountMeasurement(fetchData.amount.measurement);
                        setAmountUnit(fetchData.amount.unit);
                        setCountNum(fetchData.count.num);
                        setCountUnit(fetchData.count.unit);
                        setDepth(fetchData.depth);
                        setDrcUpc(fetchData.drc_upc);
                        if(fetchData.drc_upc !== '') {
                            set_drc(true);
                            document.getElementById("drc_checkbox").checked = true;
                        }
                        setHeight(fetchData.height);
                        setName(fetchData.name);
                        setTemplateName(fetchData.template_name);
                        setUpc(fetchData.upc);
                        setWidth(fetchData.width);
                    }
                    fetch(process.env.API_BASE_URL+"/templates/"+encodeURIComponent(fetchData.template_name), requestOptions)
                        .then(response => response.json())
                        .then(fetchData => {
                            set_donor_shape(fetchData.donor_shape);
                            set_form_desc(fetchData.form_desc);
                            set_gltf(fetchData.gltf);
                            set_notes(fetchData.notes);
                            set_product_upc(fetchData.product_upc);
                            set_type(fetchData.type);
                            set_workflow(fetchData.workflow);
                        })
              });
        }
        return () => mounted = false;
    }, [])

    const changeTheme = (newTheme) => {
        setTheme(newTheme);
    }
    
    const updateCategory = () => {
        
        const obj = JSON.parse(localStorage.getItem("access_token"));
        const token = "Bearer " + obj.access_token;
        const cat = JSON.parse(localStorage.getItem("current_category"));
        var requestOptions = {
            method: "GET",
            headers: {
                "Authorization":token
            },
            redirect: "follow"
        };
        fetch(process.env.API_BASE_URL+"/categories/"+encodeURIComponent(cat.current_category), requestOptions)
                .then(response => response.json())
                .then(fetchData => {
                    var updated_data = fetchData.templates;
                    console.log(template_name);
                    updated_data.push(template_name);
                    requestOptions = {
                        method: "PATCH",
                        headers: {
                            "Content-Type": "application/json",
                            "Authorization":token
                        },
                        body: JSON.stringify({
                            templates:updated_data
                        }),
                        redirect: "follow"
                    }
                    fetch(procces.env.API_BASE_URL+"/categories/"+encodeURIComponent(cat.current_category), requestOptions)
                    .then(response => response.json())
                    .then(data => console.log(data))   
                });
        
    }

    const saveRecord = () => { 
        const count = {
            "measurement": count_num,
            "unit": count_unit
        }
        const amount = { 
            "measurement": amount_measurement,
            "unit": amount_unit
        }
        const product = {
            "upc": upc,
            "drc_upc": drc_upc,
            "name": name,
            "count": count,
            "amount": amount,
            "template_name": template_name,
            "width": width,
            "height": height,
            "depth": depth,
            "add_height": add_height,
            "add_info": add_info
          }
        
        const obj = JSON.parse(localStorage.getItem("access_token"));
        const token = "Bearer " + obj.access_token;

        if(props.stateVars === "new record") {
            const project = JSON.parse(localStorage.getItem("current_project"))
            const projectName = project.current_project;
            var requestOptions = {
                method: "POST",
                headers: {
                    "Authorization":token,
                    'Content-Type':'application/json'
                },
                body: JSON.stringify({
                    project_name: projectName,
                    product: product
                }),
                redirect: "follow"
            };
            console.log(projectName);
            fetch(process.env.API_BASE_URL+'/products', requestOptions)
            .then(response => {
                response.json()
            })
            .then(data => {
                console.log(data)
            })
        } else {
            console.log(props.stateVars);
            var requestOptions = {
                method: "PATCH",
                headers: {
                    "Authorization":token,
                    'Content-Type':'application/json'
                },
                body: JSON.stringify(product),
                redirect: "follow"
            };
            fetch(process.env.API_BASE_URL+'/products/'+encodeURIComponent(upc), requestOptions)
                .then(response => {
                    response.json()
            })
            .then(data => {
                console.log(data)   
            })
        }
        
        if(new_template_checkbox === "on") {
            /* add new template */
            const obj = JSON.parse(localStorage.getItem("access_token"));
            const token = "Bearer " + obj.access_token;
                 var requestOptions = {
                    method: "POST",
                    headers: {
                        "Authorization":token,
                        "Content-Type":"application/json"
                    },
                    body: JSON.stringify({
                        "donor_shape":donor_shape,
                        "form_desc":form_desc,
                        "gltf":gltf,
                        "name":template_name,
                        "notes":notes,
                        "product_upc":product_upc,
                        "type":type,
                        "workflow":workflow
                    }),
                    redirect: "follow"
                 }
                fetch(process.env.API_BASE_URL+"/templates/", requestOptions)
                    .then(response => response.json())
                    .then(data => {
                        console.log("finished adding to db");
                        updateCategory();
                    }) 
            
        }
        
        
    }

    const clearRecord = () => {
        setAddHeight('');
        setAddInfo('');
        setAmountMeasurement('');
        setAmountUnit('');
        setCountNum('');
        setCountUnit('');
        setDepth('');
        setDrcUpc('');
        setHeight('');
        setName('');
        setTemplateName('');
        setUpc('');
        setWidth('');
    }

    return(
        <div class="background" id={theme}>
            <MainHeader current_theme={theme} switchTheme={changeTheme} onSwitch={(stateName, stateVars, theme) => props.onSwitch(stateName, stateVars, theme)} />
            <table className="editrecord">
                <div className="flex-container">
                <div className="group">
                    <tr>
                        <td><h4>Record&nbsp;Name</h4></td>
                        <td><input id="elongated" className="editrecord" type="text" placeholder={name} onChange={(e) => setName(e.target.value)}></input></td>
                        <td><button className="editrecord" onClick={() => {props.onSwitch('Projects','', theme)}}>Return</button></td>
                        <td><button className="editrecord" onClick={() => saveRecord()}>Save</button></td>
                        <td><button className="editrecord" onClick={() => clearRecord()}>Clear</button></td>
                    </tr>
                </div>
    <div className="group">
                <tr>
                        <td><h5 className="editrecord">Product&nbsp;UPC</h5></td>
                        <td><h5 className="editrecord">DRC</h5></td>
                        <td><h5 className="editrecord">UPC&nbsp;of&nbsp;item&nbsp;in&nbsp;DRC</h5></td>
                        <td><h5 className="editrecord">GLTF</h5></td>
                </tr>
                <tr>
                        <td><input className="editrecord" type="text" placeHolder={upc} onChange={(e) => setUpc(e.target.value)}></input></td>
                        <td><input id="drc_checkbox" type="checkbox" onChange={(e)=> 
                        {
                            set_drc(e.target.value);
                            console.log(drc);
                        }} ></input></td>
                        <td><input className="editrecord" type="text" placeHolder={drc_upc} onChange={(e) => setDrcUpc(e.target.value)}></input></td> 
                        <td><input className="editrecord" type="text" placeHolder={gltf} onChange={(e) => set_gltf(e.target.value)}></input></td>
                </tr>
</div>
<div className="group">
                <tr>
                    <td><h5 className="editrecord">Product Name (Brand Name Flavor)</h5></td>
                </tr>
                <tr>
                    <td><input id="elongated" className="editrecord" type="text" placeholder={name} onChange={(e) => setName(e.target.value)}></input></td>
                </tr>
                        </div>
<div className="group">
                <tr>
                        <td><h5 className="editrecord">Item Count (if listed)</h5></td>
                        <td><h5 className="editrecord">Unit of measurement</h5></td>
                        <td><h5 className="editrecord">Weight / Volume</h5></td>
                        <td><h5 className="editrecord">Unit of measurement</h5></td> 
                </tr>
                <tr>
                        <td><input className="editrecord" type="text" placeholder={count_num} onChange={(e) => setCountNum(e.target.value)}></input></td>
                        <td><input className="editrecord" type="text" placeholder={count_unit} onChange={(e) => setCountUnit(e.target.value)}></input></td>
                        <td><input className="editrecord" type="text" placeholder={amount_measurement} onChange={(e) => setAmountMeasurement(e.target.value)}></input></td>
                        <td><input className="editrecord" type="text" placeholder={amount_unit} onChange={(e) => setAmountUnit(e.target.value)}></input></td> 
                </tr>
</div>
<div className="group">
                <tr>
                        <td><h5 className="editrecord">Template Name</h5></td>
                        <td><h5 className="editrecord">New</h5></td>
                        <td><h5 className="editrecord">Template Type</h5></td>
                </tr>
                <tr>
                        <td><input className="editrecord" type="text" placeholder={template_name} onChange={(e) => setTemplateName(e.target.value)}></input></td>
                        <td><input id="new_template_checkbox" type="checkbox" onChange={(e) => set_new_template_checkbox(e.target.value)}></input></td>
                        <td><input className="editrecord" type="text" placeholder={type} ></input></td> 
                </tr>
</div>
<div className="group">
                <tr>
                        <td><h5 className="editrecord">Width</h5></td>
                        <td><h5 className="editrecord">Height</h5></td>
                        <td><h5 className="editrecord">Depth</h5></td>
                        <td><h5 className="editrecord">Additional Height</h5></td>
                        <td><h5 className="editrecord">Form Description</h5></td>
                </tr>
                <tr>
                        <td><input className="editrecord" type="text" placeholder={width} onChange={(e) => setWidth(e.target.value)}></input></td>
                        <td><input className="editrecord" type="text" placeholder={height} onChange={(e) => setHeight(e.target.value)}></input></td>
                        <td><input className="editrecord" type="text" placeholder={depth} onChange={(e) => setDepth(e.target.value)}></input></td>
                        <td><input className="editrecord" type="text" placeholder={add_height} onChange={(e) => setAddHeight(e.target.value)}></input></td>
                        <td><input className="editrecord" type="text" placeholder={form_desc}></input></td>
                </tr>
</div>
<div className="group">
                <tr>
                        <td><h5 className="editrecord">Workflow</h5></td>
                </tr>
                <tr>
                        <td><input id="elongated" className="editrecord" type="text" placeholder={workflow} ></input></td>
                </tr>
</div>
<div className="group">
                <tr>
                        <td><h5 className="editrecord">Additional Information</h5></td>
                </tr>
                <tr>
                        <td><input id="elongated" className="editrecord" type="text" placeholder={add_info} onChange={(e) => setAddInfo(e.target.value)}></input></td>
                </tr>
</div>
                </div>
            </table>
        </div>
    ) 

}
