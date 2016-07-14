import collections
import idautils
import logging
import idaapi
import idc

class ReefConfig( object ):

    PLUGIN_NAME             = "Reef"
    PLUGIN_COMMENT          = "Xrefs from function"
    PLUGIN_HELP             = "www.github.com/darx0r/Reef"
    PLUGIN_HOTKEY           = "Shift-X"

    CHOOSER_TITLE           = "Reef - Xrefs from function"
    CHOOSER_COLUMN_NAMES    = [ "Direction",	"Type",	"Address",	"Text"    ]
    CHOOSER_COLUMN_SIZES    = [ 6,				7,		6,			40        ]
    CHOOSER_COLUMNS         = [ list(c) for c in 
                                zip(CHOOSER_COLUMN_NAMES, CHOOSER_COLUMN_SIZES) ]
    CHOOSER_ROW             = collections.namedtuple(    "ResultRow", 
                                                         CHOOSER_COLUMN_NAMES )

    PLUGIN_TEST                = False

    # Icon in PNG format
    PLUGIN_ICON_PNG =    (
        "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52"
        "\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1F\xF3\xFF"
        "\x61\x00\x00\x00\x8D\x49\x44\x41\x54\x38\x8D\xED\xD0\xA1\x0D\xC2"
        "\x50\x14\x85\xE1\x4F\x20\x10\x48\x04\x02\x81\x44\x74\x00\x64\x05"
        "\x03\x20\x18\xA0\x12\xC9\x00\xEC\x81\x40\x32\x00\x23\x20\x3A\x02"
        "\x82\x41\x10\x08\x04\x98\x4B\x52\x9A\xD7\xD7\x04\xDD\x3F\x39\xE6"
        "\xDD\x73\x73\xFF\x3C\x06\x72\x8C\x31\xFF\x77\x79\x86\x3B\x6A\x54"
        "\xD8\xA0\xC0\xA4\xEF\x62\x89\x13\x1E\x78\x27\x72\x8C\x5E\x92\x43"
        "\xC7\x52\x2A\x2F\xDC\xB0\x16\x5A\x25\x2E\x31\x68\x96\xCE\x0D\xA3"
        "\x2B\x76\x78\xC6\xF2\xF2\x7B\x79\x11\x5A\xAB\xC8\x36\xDE\xA6\x61"
        "\x35\x6A\x99\xEE\x63\xDE\x49\xD1\x57\x08\xE3\x2C\xD9\xDF\x1E\xF8"
        "\xE5\x03\xF7\xAF\x23\xB4\xA6\xA1\x55\x66\x00\x00\x00\x00\x49\x45"
        "\x4E\x44\xAE\x42\x60\x82"        )


# ------------------------------------------------------------------------------


class XrefFrom( object ):

    DIRECTION =     [	"Down",
                        "Up"	]


    def __init__( self, xrefer, to, type, text ):
            
            is_above = xrefer > to
            self.direction = XrefFrom.DIRECTION[is_above]
            self.to = to
            self.type = type
            self.text = text


    def get_row( self, type_dict ):
        
        direction = self.direction
        to = "{:08X}".format( self.to )
        
        type = "Unknown"
        if self.type in type_dict:
            type = type_dict[self.type]
        text = self.text
        
        # IDA Chooser doesn't like tuples ... row should be a list
        return list( ReefConfig.CHOOSER_ROW( direction, type, to, text ) )


class XrefsFromFinder( object ):

    XREF_TYPE2STR = {   idaapi.fl_U : "User Defined",
                        idaapi.fl_CF: "Far Call", 
                        idaapi.fl_CN: "Near Call", 
                        idaapi.fl_JF: "Far Jump", 
                        idaapi.fl_JN: "Near Jump"    }


    def __init__( self ):
        pass


    def find_xrefs_from( self, func_ea ):
    
        xrefs = []

        for item in idautils.FuncItems( func_ea ):
            
            ALL_XREFS = 0
            for ref in idautils.XrefsFrom( item, ALL_XREFS ):
                    
                if ref.type not in XrefsFromFinder.XREF_TYPE2STR:
                    continue
                
                if ref.to in idautils.FuncItems( func_ea ):
                    continue
                
                disas = idc.GetDisasm( item )
                curr_xref = XrefFrom( item, ref.to, ref.type, disas )
                xrefs.append( curr_xref )
                
        return xrefs


    def get_current_function_xrefs_from( self ):
    
        addr_in_func = idc.ScreenEA()
        curr_func = idc.GetFunctionName( addr_in_func )

        refs = self.find_xrefs_from( addr_in_func )
        return [ ref.get_row( XrefsFromFinder.XREF_TYPE2STR ) for ref in refs ]


# ------------------------------------------------------------------------------


class ReefPluginEmbeddedChooser( idaapi.Choose2 ):

    def __init__( self, title, columns, items, icon, embedded=True ):

        LIKE_XREF_FROM_WIDTH = 100
        idaapi.Choose2.__init__(    self, title, columns, embedded=embedded, 
                                    width=LIKE_XREF_FROM_WIDTH )
        self.items = items
        self.icon = icon


    def GetItems( self ):
        return self.items


    def SetItems( self, items ):
        self.items = [] if items is None else items
        self.Refresh()


    def OnClose( self ):
        pass


    def OnGetLine( self, n ):
        return self.items[n]


    def OnGetSize( self ):
        return len(self.items)


    def OnSelectLine( self, n ):

        row = ReefConfig.CHOOSER_ROW( *self.items[n] )
        to = row.Address
        idc.Jump( int(to, 16) )


# ------------------------------------------------------------------------------


PLUGIN_CHOOSER_FORM_TEMPLATE = \
r"""BUTTON YES* OK
BUTTON CANCEL Cancel
%s
<Xrefs From:{Chooser}>
"""

class ReefPluginChooserForm( idaapi.Form ):
    
    def __init__( self, title, chooser ):

        self.chooser = chooser
        template_instance = PLUGIN_CHOOSER_FORM_TEMPLATE % title
        Form.__init__(self, template_instance, {
            'Chooser' : Form.EmbeddedChooserControl(chooser)
        })


# ------------------------------------------------------------------------------


class ReefPlugin( idaapi.plugin_t ):

    flags            = 0
    comment          = ReefConfig.PLUGIN_COMMENT
    help             = ReefConfig.PLUGIN_HELP
    wanted_name      = ReefConfig.PLUGIN_NAME
    wanted_hotkey    = ReefConfig.PLUGIN_HOTKEY

    def __init__( self, *args, **kwargs ):
        
        super(ReefPlugin, self).__init__(*args, **kwargs)


    def init( self ):

        self.icon_id = idaapi.load_custom_icon( data = ReefConfig.PLUGIN_ICON_PNG, 
                                                format = "png"    )
        if self.icon_id == 0:
            raise RuntimeError("Failed to load icon data!")

        self.finder = XrefsFromFinder()

        return idaapi.PLUGIN_KEEP


    def run( self, arg=0 ):
        
        try:
            rows = self.finder.get_current_function_xrefs_from()
            chooser = ReefPluginEmbeddedChooser(    ReefConfig.CHOOSER_TITLE, 
                                                    ReefConfig.CHOOSER_COLUMNS, 
                                                    rows, 
                                                    self.icon_id    )

            self.form = ReefPluginChooserForm( ReefConfig.CHOOSER_TITLE, chooser )
            instance = self.form.Compile()
            self.form.Execute()
            self.form.Free()
            
        except Exception as e:
            logging.getLogger("Reef").warning("exception", exc_info=True)
        return


    def term( self ):

        if self.icon_id != 0:
            idaapi.free_custom_icon(self.icon_id)


# ------------------------------------------------------------------------------    


def PLUGIN_ENTRY():
    return ReefPlugin()


# ------------------------------------------------------------------------------


if ReefConfig.PLUGIN_TEST:
    print "{} - test".format(ReefConfig.PLUGIN_NAME)
    p = ReefPlugin()
    p.init()
    p.run()
    p.term()

