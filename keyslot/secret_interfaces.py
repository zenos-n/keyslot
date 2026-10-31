"""Secret Service 0.2 interfaces; GDBus handles introspection and signature checks."""
from gi.repository import Gio

ROOT = "/org/freedesktop/secrets"
NAME = "org.freedesktop.secrets"
PREFIX = "org.freedesktop.Secret."
PROPERTIES = "org.freedesktop.DBus.Properties"

XML = '''<node>
<interface name="org.freedesktop.Secret.Service">
  <method name="OpenSession"><arg type="s" direction="in"/><arg type="v" direction="in"/><arg type="v" direction="out"/><arg type="o" direction="out"/></method>
  <method name="CreateCollection"><arg type="a{sv}" direction="in"/><arg type="s" direction="in"/><arg type="o" direction="out"/><arg type="o" direction="out"/></method>
  <method name="SearchItems"><arg type="a{ss}" direction="in"/><arg type="ao" direction="out"/><arg type="ao" direction="out"/></method>
  <method name="Unlock"><arg type="ao" direction="in"/><arg type="ao" direction="out"/><arg type="o" direction="out"/></method>
  <method name="Lock"><arg type="ao" direction="in"/><arg type="ao" direction="out"/><arg type="o" direction="out"/></method>
  <method name="GetSecrets"><arg type="ao" direction="in"/><arg type="o" direction="in"/><arg type="a{o(oayays)}" direction="out"/></method>
  <method name="ReadAlias"><arg type="s" direction="in"/><arg type="o" direction="out"/></method>
  <method name="SetAlias"><arg type="s" direction="in"/><arg type="o" direction="in"/></method>
  <property name="Collections" type="ao" access="read"/>
  <signal name="CollectionCreated"><arg type="o"/></signal>
  <signal name="CollectionDeleted"><arg type="o"/></signal>
  <signal name="CollectionChanged"><arg type="o"/></signal>
</interface>
<interface name="org.freedesktop.Secret.Collection">
  <method name="Delete"><arg type="o" direction="out"/></method>
  <method name="SearchItems"><arg type="a{ss}" direction="in"/><arg type="ao" direction="out"/></method>
  <method name="CreateItem"><arg type="a{sv}" direction="in"/><arg type="(oayays)" direction="in"/><arg type="b" direction="in"/><arg type="o" direction="out"/><arg type="o" direction="out"/></method>
  <property name="Items" type="ao" access="read"/>
  <property name="Label" type="s" access="readwrite"/>
  <property name="Locked" type="b" access="read"/>
  <property name="Created" type="t" access="read"/>
  <property name="Modified" type="t" access="read"/>
  <signal name="ItemCreated"><arg type="o"/></signal>
  <signal name="ItemDeleted"><arg type="o"/></signal>
  <signal name="ItemChanged"><arg type="o"/></signal>
</interface>
<interface name="org.freedesktop.Secret.Item">
  <method name="Delete"><arg type="o" direction="out"/></method>
  <method name="GetSecret"><arg type="o" direction="in"/><arg type="(oayays)" direction="out"/></method>
  <method name="SetSecret"><arg type="(oayays)" direction="in"/></method>
  <property name="Locked" type="b" access="read"/>
  <property name="Attributes" type="a{ss}" access="readwrite"/>
  <property name="Label" type="s" access="readwrite"/>
  <property name="Created" type="t" access="read"/>
  <property name="Modified" type="t" access="read"/>
</interface>
<interface name="org.freedesktop.Secret.Session"><method name="Close"/></interface>
<interface name="org.freedesktop.Secret.Prompt">
  <method name="Prompt"><arg type="s" direction="in"/></method>
  <method name="Dismiss"/>
  <signal name="Completed"><arg type="b"/><arg type="v"/></signal>
</interface>
</node>'''

INTERFACES = {info.name.removeprefix(PREFIX).lower(): info for info in Gio.DBusNodeInfo.new_for_xml(XML).interfaces}
