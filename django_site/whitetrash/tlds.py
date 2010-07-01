class TLDHelper():

    def __init__(self,filepath):
        self.list = {}
        self.build_rules_dict(filepath)

    def build_rules_dict(self,filepath):

        #List of TLDS used in wildcarding code.
        #Source: http://publicsuffix.org/
        with open(filepath) as tldFile:
            for line in tldFile:
                if line[0] not in "/\n":
                    self.add_rule(line.strip().rsplit("."),self.list)

    def add_rule(self,rule,ruledict):
        try:
            label = rule.pop()
            if label not in ruledict:
                ruledict[label] = {}

            ruledict[label] = self.add_rule(rule,ruledict[label])
            return ruledict
        except IndexError:
            return ruledict 

    def is_public(self,domain):

        def find_match(dom,ruledict):
            try:
                label = dom.pop()
                nlabel = "!%s" % label

                if nlabel in ruledict:
                    #As soon as an exception matches we can
                    #stop looking - this isn't a public suffix
                    return False

                if label in ruledict:
                    #Most labels is next in matching hierarchy, so look as
                    #deep as possible first
                    if ruledict[label]:
                        return find_match(dom,ruledict[label])
                    else:
                        #Ran out of rules before domains - this is
                        #not a public suffix
                        return False
                        
                #TODO: not working right for blah.com
                if "*" in ruledict:
                    if dom:
                        #More domain left, so not a pub suffix
                        return False
                    else:
                        return True
                else:
                    #no matches default is "*"
                    return True

            except IndexError:
                #We ran out of domain before we ran out of rules
                #This must be a public suffix
                return True 

        dom = domain.split(".")
        return find_match(dom,self.list)
        

a=TLDHelper("effective_tld_names.dat")
a.is_public("testing.com")
