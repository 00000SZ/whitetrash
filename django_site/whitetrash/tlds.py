
class TLDHelper():
    """Provides checking of domains to determine if they match a public suffix.

    Public suffix list from http://publicsuffix.org/
    The idea is we won't let users whitelist a whole public suffix (like co.uk)"""

    def __init__(self,filepath):
        self.list = {}
        self.build_rules_dict(filepath)

    def build_rules_dict(self,filepath):
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
        """Is this domain a public suffix? 

        Note: If no rules match (e.g. if you were checking "myprivate.lan") the prevailing
        rule is a single "*", which means it isn't public (but "lan" would be)."""

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
                        if find_match(dom,ruledict[label]):
                        	return True
                        #If we didn't find any matches we need to test
                        #for the *rule below
                    elif dom:
                        #Ran out of rules before domains - this is
                        #not a public suffix
                        return False
                    else:
                        #exact match
                        return True
                        
                if "*" in ruledict and not dom:
                	#No more labels, the * matches.
                    return True
                else:
                    return False
            
            except IndexError:
                #We ran out of domain before we ran out of rules
                #This must be a public suffix
                return True 

        dom = domain.split(".")
        if dom[-1] not in self.list:
        	#If not a valid TLD
        	#"lan" is public but "testbox.lan" is not
        	return len(dom) == 1
        return find_match(dom,self.list)
        
