"""GraphML and Maltego format exporters."""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
from xml.dom import minidom

import networkx as nx

MALTEGO_MAP: dict[str, str] = {
    "Person": "maltego.Person",
    "Email": "maltego.EmailAddress",
    "Username": "maltego.Alias",
    "Phone": "maltego.PhoneNumber",
    "Platform": "maltego.URL",
    "Domain": "maltego.Domain",
    "IP": "maltego.IPv4Address",
    "Location": "maltego.Location",
    "Organization": "maltego.Organization",
    "Image": "maltego.Image",
}


class GraphExporter:
    """Exports a NetworkX graph to GraphML or Maltego XML."""

    def export_graphml(self, graph: nx.MultiDiGraph) -> str:
        """Return the graph serialised as a GraphML string."""
        buf = io.BytesIO()
        nx.write_graphml(graph, buf)
        return buf.getvalue().decode("utf-8")

    def export_maltego(self, graph: nx.MultiDiGraph) -> str:
        """Return a Maltego-compatible XML response string."""
        root = ET.Element("MaltegoMessage")
        response = ET.SubElement(root, "MaltegoTransformResponseMessage")
        entities_elem = ET.SubElement(response, "Entities")

        for node_id, data in graph.nodes(data=True):
            node_type = data.get("node_type", "Person")
            maltego_type = MALTEGO_MAP.get(node_type, "maltego.Unknown")
            value = str(data.get("value", node_id))

            entity = ET.SubElement(entities_elem, "Entity")
            entity.set("Type", maltego_type)

            value_elem = ET.SubElement(entity, "Value")
            value_elem.text = value

            if extra := {k: v for k, v in data.items() if k not in ("node_type", "value") and v}:
                fields = ET.SubElement(entity, "AdditionalFields")
                for k, v in extra.items():
                    field = ET.SubElement(fields, "Field")
                    field.set("Name", k)
                    field.text = str(v)

        raw = ET.tostring(root, encoding="unicode")
        return minidom.parseString(raw).toprettyxml(indent="  ")
