import drawpyo
import csv
import ipaddress
import os
import sys
import math
def sort_ip(x):
    ip_obj = ipaddress.ip_address(x['ip'])
    subnet_obj = ipaddress.ip_network(x['subnet'])
    return (
        ip_obj.version,      
        subnet_obj,          
        ip_obj,              
        x['os'].lower(),
        x['hostname'].lower()
    )
def parse_csv(file="input.csv"):
    hosts = []
    headers = ["subnet","ip","hostname","os","services"]
    headers_matches = [
        ["sub","net"],
        ["ip"],
        ["host","name"],
        ["os","operat"],
        ["service","scor","special","note"]
    ]
    with open(file, 'r') as file:
        reader = csv.reader(file, delimiter=',')
        rowindex = 1
        for row in reader:
            if len(row) != 0:
                if len(row) < len(headers):
                    raise ValueError(f"Provided input file does not have enough columns on row {rowindex}!")
                if rowindex == 1:
                    for i in range(0,len(headers)):
                        condition=False
                        for match in headers_matches[i]:
                            if match in row[i].lower():
                                condition = True
                        if not condition:
                            print(f"Column {i} fails soft validity check, are you sure that your columns are set up correctly? Expected value relating to {headers[i]}")
                else:
                    entry = dict(zip(headers, row[:5]))
                    hosts.append(entry)
            rowindex += 1
    hosts.sort(key=sort_ip)
    return hosts
def get_os_string(full_os_str):
    full_os_str = full_os_str.lower()
    if "internet" in full_os_str:
        return "https://static.wikia.nocookie.net/cloudss/images/9/94/The_Clouds_Wiki_Icon.png"
    if "router" in full_os_str:
        return "https://symbols.getvecta.com/stencil_240/204_router.7b208c1133.png"
    if "windows server" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/8/87/Windows_logo_-_2021.svg/960px-Windows_logo_-_2021.svg.png?20220927154043"
    if "windows" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/4/48/Windows_logo_-_2012_%28dark_blue%29.svg/250px-Windows_logo_-_2012_%28dark_blue%29.svg.png"
    if "ubuntu" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/9/9e/UbuntuCoF.svg/1200px-UbuntuCoF.svg.png"
    if "fedora" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/4/41/Fedora_icon_%282021%29.svg/1280px-Fedora_icon_%282021%29.svg.png"
    if "debian" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/6/66/Openlogo-debianV2.svg/640px-Openlogo-debianV2.svg.png"
    if "alpine" in full_os_str:
        return "https://distrosea.com/distro-icons/alpine.svg"
    if "rocky" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/7/77/Rocky_Linux_logo.svg"
    if "centos" in full_os_str:
        return "https://commons.wikimedia.org/wiki/File:CentOS_color_logo.svg"
    if "rhel" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/d/d8/Red_Hat_logo.svg/960px-Red_Hat_logo.svg.png"
    if "amazon" in full_os_str:
        return "https://icon2.cleanpng.com/20180817/vog/8968d0640f2c4053333ce7334314ef83.webp"
    if "suse" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/d/d1/OpenSUSE_Button.svg/640px-OpenSUSE_Button.svg.png"
    if "solaris" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/2/25/Solaris_9_logo.svg/960px-Solaris_9_logo.svg.png"
    return "https://symbols.getvecta.com/stencil_240/79_fileserver.c500813aaa.png"
def draw_main(hosts,file_path,file_name,max_host_per_row = 4):
    file = drawpyo.File()
    file.file_path = file_path
    file.file_name = file_name
    page = drawpyo.Page(file=file)
    page.grid = 0
    page.background = "#ffffff"
    text = drawpyo.diagram.text_format.TextFormat(
        fontColor='#000000',
        fontFamily='Helvetica', 
        fontSize=10,
        align='center',
        direction='horizontal',
        labelPosition='center',
    )
    texttitle = drawpyo.diagram.text_format.TextFormat(
        fontColor='#000000',
        fontFamily='Helvetica',
        fontSize=16,
        align='center',
        direction='horizontal',
        labelPosition='center',
        bold=1
    )
    textrouter = drawpyo.diagram.text_format.TextFormat(
        fontColor='#000000',
        fontFamily='Helvetica',
        fontSize=10,
        align='center',
        direction='horizontal',
        labelPosition='center',
        verticalAlign='bottom',
        spacingBottom=45
    )
    textinternet = drawpyo.diagram.text_format.TextFormat(
        fontColor='#000000',
        fontFamily='Helvetica',
        fontSize=10,
        align='center',
        direction='horizontal',
        labelPosition='center',
        verticalAlign='bottom',
        spacingBottom=60
    )
    subnets = {}
    for host in hosts:
        s = host["subnet"]
        if s not in subnets:
            subnets[s] = []
        subnets[s].append(host)
    colors = [
        ["#2D8A5B", "#F0F9F4", "#144D3E"], 
        ["#7B61FF", "#F2F0FF", "#4A3BB1"], 
        ["#D97706", "#FFFBEB", "#92400E"], 
        ["#00A4A6", "#E6F6F7", "#147EBA"], 
        ["#E11D48", "#FFF1F2", "#9F1239"], 
        ["#4B5563", "#F3F4F6", "#1F2937"]  
    ]
    color_index = 0
    image_size = 75
    host_spacing = image_size + 50
    center_spacing = 50
    parent_container_width = (50*2)+((host_spacing)*max_host_per_row)
    textobj = drawpyo.diagram.Object(
        text_format=texttitle,
        value=f'Company<br/>Location<br/>FQDN',
        page=page,
        width=image_size,
        height=image_size,
        position=(parent_container_width+center_spacing,20),
        html=1,
        whiteSpace="nowrap",
        image=""
    )
    text_style = (
        "text;"
        "html=1;"
        "strokeColor=none;"
        "fillColor=none;"
        "whiteSpace=nowrap;"
    )
    textobj.apply_style_string(text_style)
    textobj.text_format = texttitle
    router = drawpyo.diagram.Object(
        value=f'Router<br/>127.0.0.1<br/>PfSense',
        page=page,
        width=image_size,
        height=image_size,
        position=(parent_container_width+center_spacing,140)
    )
    router.text_format = textrouter
    stylestring = (
        "shape=image;"
        "verticalLabelPosition=bottom;"
        "verticalAlign=top;"
        "imageAspect=0;"
        "aspect=fixed;"
        "html=1;"
        "whiteSpace=nowrap;"
        f"image={get_os_string('router')};"
    )
    router.apply_style_string(stylestring)
    internet = drawpyo.diagram.Object(
        value=f'Public Internet',
        page=page,
        width=image_size,
        height=image_size,
        position=(parent_container_width+center_spacing,330)
    )
    stylestring = (
        "shape=image;"
        "verticalLabelPosition=bottom;"
        "verticalAlign=top;"
        "imageAspect=0;"
        "aspect=fixed;"
        "html=1;"
        "whiteSpace=nowrap;"
        f"image={get_os_string('internet')};"
    )
    internet.apply_style_string(stylestring)
    internet.text_format = textinternet
    drawnSubnets = []
    num_subnets = len(subnets)
    col_y_starts = [0, 0]
    total_rows = 0
    row_counts = []
    for s_name in subnets:
        count = math.ceil(len(subnets[s_name]) / max_host_per_row)
        row_counts.append(count)
        total_rows += count
    half_rows = total_rows / 2
    cumulative_rows = 0
    split_index = 0
    use_two_columns = total_rows > 3
    for i, count in enumerate(row_counts):
        cumulative_rows += count
        split_index = i
        if cumulative_rows >= half_rows:
            break
    current_subnet_idx = 0
    current_subnet_idx = 0
    for subnet in subnets:
        drawnHosts = []
        for host in subnets[subnet]:
            item = drawpyo.diagram.Object(
                value=f'{host["hostname"]}<br/>{host["ip"]}<br/>{host["os"]}<br/>{host["services"]}', 
                page=page,
                width=image_size,
                height=image_size
            )
            stylestring = (
                "shape=image;"
                "verticalLabelPosition=bottom;"
                "verticalAlign=top;"
                "imageAspect=0;"
                "aspect=fixed;"
                "html=1;"
                "whiteSpace=nowrap;"
                f"image={get_os_string(host["os"])};"
            )
            item.apply_style_string(stylestring)
            item.text_format = text
            drawnHosts.append(item)
        parent_container = drawpyo.diagram.Object(
            page=page,
            value=f"{subnet}",
            autosize_margin=50
        )
        parent_container.apply_style_string(
            f"html=1;fontSize=12;fontStyle=0;shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_security_group;grStroke=0;strokeColor={colors[color_index][0]};fillColor={colors[color_index][1]};verticalAlign=top;align=left;spacingLeft=30;fontColor={colors[color_index][2]};dashed=0;"
        )
        color_index += 1
        if color_index >= len(colors):
            color_index = 0
        row_index, col_index = 0, 0
        for index,item in enumerate(drawnHosts,start=1):
            if col_index > max_host_per_row - 1:
                col_index = 0
                row_index += 1
            parent_container.add_object(item)
            item.position_rel_to_parent = ((col_index * host_spacing), (row_index * (host_spacing * 1.25)))
            col_index += 1
        parent_container.resize_to_children()
        connection = drawpyo.diagram.edges.Edge(
            page=page,
            source=parent_container,
            target=router,
            label="127.0.0.1",
            label_position=-1,
            label_offset=15,
            endSize=40,
            startSize=40,
            rounded=True,
            waypoints="vertical", 
            connection="link" 
        )
        parent_container.height += 25 
        if use_two_columns:
            current_col = 0 if current_subnet_idx <= split_index else 1
            if current_col == 1:
                connection.apply_style_string("label_offset=-15;")
            x_pos = current_col * (parent_container_width + (center_spacing*3) + image_size)
            parent_container.position = (x_pos, col_y_starts[current_col])
            col_y_starts[current_col] += parent_container.height + 50
        else:
            parent_container.position = (0, col_y_starts[0])
            col_y_starts[0] += parent_container.height + 50
        current_subnet_idx += 1
        drawnSubnets.append(parent_container)
    connection = drawpyo.diagram.edges.Edge(
        page=page,
        source=internet,
        target=router,
        endSize=30,
        startSize=30,
        rounded=True,
        targetPerimeterSpacing=33,
        waypoints="vertical", 
        connection="link" 
    )
    file.write()
def main():
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = "input.csv"
    if len(sys.argv) > 2:
        max_host_per_row = int(sys.argv[2])
    else:
        max_host_per_row = 4
    file_path = os.getcwd()
    file_name = "network_diagram.drawio"
    print("Parsing input file...")
    hosts = parse_csv(input_file)
    print("Parsed and sorted hosts.")
    print("Drawing diagram...")
    draw_main(hosts,file_path,file_name,max_host_per_row)
    print(f"Diagram generated at {file_path}{file_name}")
main()