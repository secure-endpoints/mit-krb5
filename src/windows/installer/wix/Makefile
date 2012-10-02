
# Build language
LANG=1033

!IF !DEFINED(WIX)
WIX=c:\tools\wix.2.0.5325
!ENDIF

# Program macros
CANDLE=$(WIX)\candle -nologo

LIGHT=$(WIX)\light -nologo

CD=cd

RM=del

MAKE=nmake -nologo


# Targets

OUTPATH=.

OBJFILE=$(OUTPATH)\kfw.wixobj

MSIFILE=$(OUTPATH)\kfw.msi

!IF ("$(CPU)" == "i386")
WOW64_OBJFILE=$(OUTPATH)\kfw_wow64.wixobj

WOW64_MSIFILE=$(OUTPATH)\kfw_wow64.msi
!ENDIF

WIXINCLUDES= \
	config.wxi \
	features.wxi \
	files.wxi \
	property.wxi \
	site-local.wxi \
	lang\strings_$(LANG).wxl \
	lang\ui_$(LANG).wxi \
	lang\config_$(LANG).wxi

CUSTOMDLL=custom\custom.dll

all: $(MSIFILE) $(WOW64_MSIFILE)

$(OBJFILE): kfw.wxs $(WIXINCLUDES)
	$(CANDLE) -out $@ kfw.wxs \
		"-dDate=%DATE%" \
		"-dTime=%TIME%" \
		-dBuildLang=$(LANG)

$(MSIFILE): $(OBJFILE) $(CUSTOMDLL)
	$(LIGHT) -out $@ $(OBJFILE) \
		-loc lang\strings_$(LANG).wxl

!IF ("$(CPU)" == "i386")
$(WOW64_OBJFILE): kfw-wow64.wxs $(WIXINCLUDES)
	$(CANDLE) -out $@ kfw-wow64.wxs \
		"-dDate=%DATE%" \
		"-dTime=%TIME%" \
		-dBuildLang=$(LANG)

$(WOW64_MSIFILE): $(WOW64_OBJFILE) $(CUSTOMDLL)
	$(LIGHT) -out $@ $(WOW64_OBJFILE) \
		-loc lang\strings_$(LANG).wxl
!ENDIF

$(CUSTOMDLL): custom\custom.cpp
	$(CD) custom
	$(MAKE) -f custom.cpp
	$(CD) ..

clean:
	-$(RM) $(OBJFILE)
	-$(RM) $(MSIFILE)
!IF ("$(CPU)" == "i386")
	-$(RM) $(WOW64_OBJFILE)
	-$(RM) $(WOW64_MSIFILE)
!ENDIF
	$(CD) custom
	$(MAKE) -f custom.cpp clean
	$(CD) ..
