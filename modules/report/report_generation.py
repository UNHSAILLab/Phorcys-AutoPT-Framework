class Report:

    def __init__(self, data):
        self.data = data


    def generate_report(self):
        f = open("report.html", "x")

        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Phorcys Report</title>

<!--    -->

</head>
<body style="margin: 0px">

    <div>   <!--  Logo and intro info  -->

        <img src="images/phorcys_cropped.png" alt="" style="max-height: 20rem; display: block; margin: 0 auto">
        <h1 style=""></h1>

    </div>
""")

        hosts = [i for i in self.data.keys()] # Get Hosts

        for ip in hosts:

            f.write(f""" <div style="border: black; border-style: dashed; margin-top: 2rem"></div> <!-- port divider line -->

    <div>   <!--  Host Level  -->

        <h1 style="font-family: Verdana; padding-left: 1rem">Host - {ip} </h1>

        <div style="border: black; border-style: dashed"></div> <!-- port divider line -->

        <h2 style="font-family: Verdana; padding-left: 1rem; padding-top: 1rem">Open Ports Found:</h2>      """)

            ports = [i for i in self.data[ip].keys()]

            for port_number in ports:
                exploit = self.data[ip][port_number]['exploit']
                accessLevel = self.data[ip][port_number]['userlevel']
                output = self.data[ip][port_number]['output']

                f.write(f"""<h3 style="font-family: Verdana; padding-left: 1rem; padding-top: 1rem">Port {port_number}:</h3>

        <div style="background-color: #EEEEEE; margin-left: 5rem; margin-right: 5rem; padding-bottom: 1rem; border: black; border-style: solid; border-radius: .6rem"> <!-- Vuln Level -->

            <h3 style ="font-family: Verdana; padding-left: 1rem; padding-top: 1rem">Vulnerability: {exploit}</h3>
            <h4 style="font-family: Verdana; padding-left: 1rem; padding-top: 1rem">Access Level: {accessLevel}</h4>
            <h5 style="font-family: Verdana; padding-left: 1rem; padding-top: 1rem">Vulnerability Description:</h5>
            <p style="font-family: Verdana; padding-left: 1rem">{output}</p>
            
        </div>""")

