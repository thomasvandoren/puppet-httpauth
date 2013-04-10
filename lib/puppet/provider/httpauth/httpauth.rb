begin
    require 'webrick'
rescue
    Puppet.warning "You need WEBrick installed to manage HTTP Authentication files."
end

Puppet::Type.type(:httpauth).provide(:httpauth) do
    desc "Manage HTTP Basic and Digest authentication files"

    def create
        # Create a user in the file we opened in the mech method
        @htauth.set_passwd(resource[:realm], resource[:name], resource[:password])
        @htauth.flush
        set_file_permissions()
    end
 
    def destroy
        # Delete a user in the file we opened in the mech method
        @htauth.delete_passwd(resource[:realm], resource[:name])
        @htauth.flush
    end
 
    def exists?
        # Check if the file exists at all
        if not File.exists?(resource[:file])
            # If the file doesn't exist then create it
            File.new(resource[:file], "w").close
            mech(resource[:file])
            return false
        else
            # If it does exist open the file
            mech(resource[:file])

            # Check if the user exists in the file
            cp = @htauth.get_passwd(resource[:realm], resource[:name], false)
            return false if cp == nil

            # Check if the current password matches the proposed password
            if not check_passwd(resource[:realm], resource[:name], resource[:password], cp)
                return false
            # Check that the file has the correct permissions.
            else
                return check_file()
            end
        end
    end

    # Open the password file
    def mech(file)
        if resource[:mechanism] == :digest 
            @htauth = WEBrick::HTTPAuth::Htdigest.new(file)
        elsif resource[:mechanism] == :basic
            @htauth = WEBrick::HTTPAuth::Htpasswd.new(file)
        end
    end

    # Check file permissions (mode), uid (owner), and gid (group)
    def check_file()
        if not File.exists?(resource[:file])
            return false
        end
        fstat = File.stat(resource[:file])
        return (fstat.mode.to_s(8).end_with?(resource[:mode]) and
                fstat.uid == Etc.getpwnam(resource[:owner]).uid and
                fstat.gid == Etc.getgrnam(resource[:group]).gid)
    end

    # Check password matches
    def check_passwd(realm, user, password, cp)
        if resource[:mechanism] == :digest
            WEBrick::HTTPAuth::DigestAuth.make_passwd(realm, user, password) == cp
        elsif resource[:mechanism] == :basic
            # Can't ask webbrick as it uses a random seed
            password.crypt(cp[0,2]) == cp
        end
    end

    # Ensure file permissions (mode), uid (owner), and gid (group) are set.
    # Caller is responsible for determining the need for this.
    def set_file_permissions()
        File.open(resource[:file], "r") do |fp|
            fp.chmod(resource[:mode].to_i(8))
            fp.chown(Etc.getpwnam(resource[:owner]).uid, Etc.getgrname(resource[:group]).gid)
        end
    end
end
